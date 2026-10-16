#include "session/image/sendable.hpp"

#include <vips/vips.h>

#include <algorithm>
#include <memory>
#include <stdexcept>

#include "jpeg_encode.hpp"
#include "session/attachments.hpp"
#include "session/image/probe.hpp"
#include "source_internal.hpp"
#include "thumbnail_internal.hpp"
#include "vips_internal.hpp"

namespace session::image {

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

std::optional<Sendable> sendable(Source& source, size_t max_encrypted_size) {
    auto info = probe(source);
    if (!info || !detail::acceptable(*info) || !info->within_pixel_limits(true))
        throw std::runtime_error{"sendable: not a picture this build decodes"};

    const bool animated = info->animated();
    const bool webp = animated || info->has_alpha;
    uint32_t box = std::min(sendable_edge, std::max(info->width, info->height));

    try {
        while (true) {
            for (int quality : sendable_qualities) {
                // A fresh pipeline each time: libvips decodes lazily, and a second encode of the
                // same image would read its source again from where the first one left it.
                auto img = detail::scaled(source, *info, box, box, /*crop=*/false, animated);
                const uint32_t frames =
                        animated ? static_cast<uint32_t>(vips_image_get_n_pages(img.get())) : 1;
                const uint32_t height =
                        animated ? static_cast<uint32_t>(vips_image_get_page_height(img.get()))
                                 : static_cast<uint32_t>(img->Ysize);
                auto bytes = webp ? encode_webp(img.get(), quality)
                                  : detail::encode_jpeg(img.get(), quality);
                if (attachment::encrypted_size(bytes.size()) <= max_encrypted_size)
                    return Sendable{
                            std::move(bytes),
                            webp ? "image/webp" : "image/jpeg",
                            static_cast<uint32_t>(img->Xsize),
                            height,
                            frames};
            }
            if (box <= min_sendable_edge)
                return std::nullopt;
            box = std::max(min_sendable_edge, box * 4 / 5);
        }
    } catch (...) {
        detail::source_access::rethrow_error(source);
        throw;
    }
}

}  // namespace session::image
