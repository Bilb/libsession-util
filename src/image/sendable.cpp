#include "session/image/sendable.hpp"

#include <vips/vips.h>

#include <algorithm>
#include <cmath>
#include <memory>
#include <span>
#include <stdexcept>

#include "jpeg_encode.hpp"
#include "session/attachments.hpp"
#include "session/image/content_types.hpp"
#include "session/image/probe.hpp"
#include "source_internal.hpp"
#include "thumbnail_internal.hpp"
#include "vips_internal.hpp"

namespace session::image {

using detail::Reencoded;

namespace {

    // libwebp's speed and size trade-off, 0 to 6: 4 is its default.
    constexpr int WEBP_EFFORT = 4;

    std::vector<std::byte> encode_webp(VipsImage* img, int quality) {
        auto srgb = detail::to_srgb8(img);
        void* buf = nullptr;
        size_t len = 0;
        // libvips writes whatever metadata the image carries unless told to keep none; the
        // animation's frame delays and loop count are not metadata and are always written.
        if (vips_webpsave_buffer(
                    srgb.get(),
                    &buf,
                    &len,
                    "Q",
                    quality,
                    "effort",
                    WEBP_EFFORT,
                    "keep",
                    VIPS_FOREIGN_KEEP_NONE,
                    nullptr))
            detail::throw_vips_error("sendable: WebP encoding failed");
        std::unique_ptr<void, decltype(&g_free)> owned{buf, &g_free};
        auto* p = static_cast<const std::byte*>(buf);
        return {p, p + len};
    }

}  // namespace

Reencoded detail::reencode(Source& source, const Info& info, uint32_t box, int quality) {
    const bool animated = info.animated();
    auto img = scaled(source, info, box, box, /*crop=*/false, animated);
    Reencoded out;
    // From the decoded picture rather than the header, which a platform decoder need not agree
    // with: JPEG cannot hold the alpha band it would be handed.
    out.webp = animated || vips_image_hasalpha(img.get());
    out.width = static_cast<uint32_t>(img->Xsize);
    out.frames = animated ? static_cast<uint32_t>(vips_image_get_n_pages(img.get())) : 1;
    out.height = animated ? static_cast<uint32_t>(vips_image_get_page_height(img.get()))
                          : static_cast<uint32_t>(img->Ysize);
    out.bytes = out.webp ? encode_webp(img.get(), quality) : encode_jpeg(img.get(), quality);
    return out;
}

SendableVerdict sendable_verdict(const Info& info) {
    if (!info.decodable || info.first_frame_only())
        return SendableVerdict::cannot_decode;
    if (!detail::acceptable(
                info, std::min(sendable_edge, std::max(info.width, info.height)), false) ||
        !info.within_pixel_limits(true))
        return SendableVerdict::too_large;
    return SendableVerdict::encode;
}

SendPlan send_plan(
        Source& source, std::optional<std::string_view> content_type, uint64_t max_encrypted_size) {
    // The plaintext first, which encryption only grows, so that the cast cannot truncate.
    const bool fits =
            source.size() <= max_encrypted_size &&
            attachment::encrypted_size(static_cast<size_t>(source.size())) <= max_encrypted_size;
    auto info = probe(source);
    if (!info) {
        if (recognized(source))
            return SendPlan::unreadable;
        if (!fits)
            return SendPlan::too_large_for_server;
        return content_type && declares_image(*content_type) ? SendPlan::original_cannot_decode
                                                             : SendPlan::as_is;
    }
    switch (sendable_verdict(*info)) {
        case SendableVerdict::cannot_decode:
            if (!fits)
                return SendPlan::too_large_for_server;
            return info->first_frame_only() ? SendPlan::original_animated_png
                                            : SendPlan::original_cannot_decode;
        case SendableVerdict::too_large: return SendPlan::too_large_to_decode;
        case SendableVerdict::encode: break;
    }
    return SendPlan::reencoded;
}

std::optional<Sendable> sendable(Source& source, size_t max_encrypted_size) {
    auto info = probe(source);
    if (!info || sendable_verdict(*info) != SendableVerdict::encode)
        throw std::runtime_error{"sendable: not a picture this build re-encodes"};

    uint32_t box = std::min(sendable_edge, std::max(info->width, info->height));
    try {
        // Every quality at the full size, then the lowest only, at a box sized from how far the
        // last attempt overshot: each attempt is a whole decode and encode.
        size_t attempts = 0;
        while (true) {
            std::span<const int> qualities = sendable_qualities;
            if (attempts > 0)
                qualities = qualities.last(1);
            size_t last = 0;
            for (int quality : qualities) {
                // A fresh pipeline each time: libvips decodes lazily, and a second encode of the
                // same image would read its source again from where the first one left it.
                auto r = detail::reencode(source, *info, box, quality);
                attempts++;
                last = attachment::encrypted_size(r.bytes.size());
                if (last <= max_encrypted_size)
                    return Sendable{
                            std::move(r.bytes),
                            r.webp ? "image/webp" : "image/jpeg",
                            r.width,
                            r.height,
                            r.frames};
            }
            if (box <= min_sendable_edge || attempts >= max_sendable_attempts)
                return std::nullopt;
            // Size goes roughly with area, so the edge with its square root.
            double scale = std::clamp(
                    std::sqrt(double(max_encrypted_size) / double(last)) * 0.95, 0.5, 0.9);
            box = std::max(min_sendable_edge, static_cast<uint32_t>(box * scale));
        }
    } catch (...) {
        detail::source_access::rethrow_error(source);
        throw;
    }
}

}  // namespace session::image
