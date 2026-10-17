#include "session/image/thumbnail.hpp"

#include <vips/vips.h>

#include <algorithm>
#include <memory>

#include "jpeg_encode.hpp"
#include "platform.hpp"
#include "session/image/probe.hpp"
#include "session/image/thumbhash.hpp"
#include "source_internal.hpp"
#include "thumbnail_internal.hpp"
#include "vips_internal.hpp"

namespace session::image {

namespace detail {

    image_ptr to_srgb8(VipsImage* img) {
        VipsImage* out;
        if (vips_colourspace(img, &out, VIPS_INTERPRETATION_sRGB, nullptr))
            throw_vips_error("thumbnail: colour conversion failed");
        image_ptr srgb{out};
        if (srgb->BandFmt != VIPS_FORMAT_UCHAR) {
            if (vips_cast_uchar(srgb.get(), &out, nullptr))
                throw_vips_error("thumbnail: conversion to 8 bits failed");
            srgb.reset(out);
        }
        return srgb;
    }

    namespace {

        constexpr int CHECKER_SQUARE = 8;
        constexpr unsigned CHECKER_LIGHT = 0xFF, CHECKER_DARK = 0xCC;

        // Peak bytes over pixels measured with this build's libvips 8.18, rounded up, at 8 bits a
        // sample and over.  HEIC goes through libheif as AVIF does.
        uint64_t whole_decode_bytes_per_pixel(const Info& info) {
            bool deep = info.bits_per_sample > 8;
            switch (info.format) {
                case Format::jpeg:
                case Format::webp: return 10;
                case Format::gif: return 6;
                case Format::png: return deep ? 10 : 6;
                case Format::heic:
                case Format::avif: return deep ? 27 : 15;
            }
            return 27;
        }

        // Blended by hand rather than with vips_composite: at thumbnail size the pixels fit in a
        // few MiB, and one pass over them beats building a second image for libvips to blend.
        image_ptr over_checkerboard(VipsImage* in) {
            auto img = to_srgb8(in);
            if (img->Bands != 4)
                throw std::runtime_error{"thumbnail: expected RGBA after conversion"};

            size_t len = 0;
            std::unique_ptr<uint8_t, decltype(&g_free)> rgba{
                    static_cast<uint8_t*>(vips_image_write_to_memory(img.get(), &len)), &g_free};
            if (!rgba)
                throw_vips_error("thumbnail: decoding failed");

            int w = img->Xsize, h = img->Ysize;
            std::vector<uint8_t> rgb(size_t(w) * h * 3);
            const uint8_t* src = rgba.get();
            uint8_t* dst = rgb.data();
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++, src += 4, dst += 3) {
                    unsigned bg = ((x / CHECKER_SQUARE + y / CHECKER_SQUARE) & 1) ? CHECKER_DARK
                                                                                  : CHECKER_LIGHT;
                    unsigned a = src[3];
                    for (int c = 0; c < 3; c++)
                        dst[c] = static_cast<uint8_t>((src[c] * a + bg * (255 - a) + 127) / 255);
                }

            VipsImage* raw = vips_image_new_from_memory_copy(
                    rgb.data(), rgb.size(), w, h, 3, VIPS_FORMAT_UCHAR);
            if (!raw)
                throw_vips_error("thumbnail: cannot wrap the composited pixels");
            image_ptr out{raw};
            VipsImage* tagged;
            if (vips_copy(out.get(), &tagged, "interpretation", VIPS_INTERPRETATION_sRGB, nullptr))
                throw_vips_error("thumbnail: setting the colour space failed");
            return image_ptr{tagged};
        }

        image_ptr over_white(VipsImage* in) {
            auto img = to_srgb8(in);
            VipsArrayDouble* white = vips_array_double_newv(3, 255.0, 255.0, 255.0);
            VipsImage* out;
            int rc = vips_flatten(img.get(), &out, "background", white, nullptr);
            vips_area_unref(VIPS_AREA(white));
            if (rc)
                throw_vips_error("thumbnail: flattening failed");
            return image_ptr{out};
        }

    }  // namespace

    uint32_t jpeg_shrink(const Info& info, uint32_t box, bool crop) {
        // As vips_thumbnail chooses it: to the box's side by the picture's shorter side for a
        // cover, its longer for a fit, leaving at least a factor of two to the resize after.
        double shrink = double(crop ? std::min(info.width, info.height)
                                    : std::max(info.width, info.height)) /
                        std::max(box, 1u);
        return shrink >= 16 ? 8 : shrink >= 8 ? 4 : shrink >= 4 ? 2 : 1;
    }

    uint64_t whole_decode_bytes(const Info& info, uint32_t box, bool crop) {
        if (info.coefficient_bytes) {
            // What a progressive decode takes beyond a baseline one.  Measured at 45 MP: within 1%
            // under and 3% over for a thumbnail; for a full-size send the output term is all
            // margin, the extra being the coefficients alone.
            uint64_t s = jpeg_shrink(info, box, crop);
            return info.coefficient_bytes +
                   (info.width + s - 1) / s * ((info.height + s - 1) / s) * info.bands;
        }
        return uint64_t{info.width} * info.height * whole_decode_bytes_per_pixel(info);
    }

    bool acceptable(const Info& info, uint32_t box, bool crop) {
        return info.decodable && info.within_pixel_limits(false) && info.width && info.height &&
               !(info.decoded_whole &&
                 whole_decode_bytes(info, box, crop) > max_whole_decode_bytes);
    }

    // vips_thumbnail applies EXIF orientation, loads the first frame of an animation unless told
    // to load them all, and shrinks on load where the format allows (JPEG, WebP, HEIF), so a 12 MP
    // photo is never decoded at full size.  It converts from an embedded ICC profile only when
    // given an output profile.  Never enlarging is what the fit needs; a cover is given a box no
    // larger than the picture, so it is never asked to.
    image_ptr scaled(
            Source& source,
            const Info& info,
            uint32_t width,
            uint32_t height,
            bool crop,
            bool all_frames) {
        VipsImage* out = nullptr;
        int rc;
        auto w = static_cast<int>(width), h = static_cast<int>(height);
        if (platform_decodes(info.format)) {
            // Decoded at a size the fit below only ever shrinks: for a cover, the one whose
            // shorter side is the box's; for a fit, the box's longer side.  The platform may round
            // that a pixel short, which the cover then scales back up by that pixel.
            uint64_t longer = std::max(info.width, info.height),
                     shorter = std::min(info.width, info.height);
            uint32_t max_side =
                    crop ? static_cast<uint32_t>(
                                   (longer * std::min(width, height) + shorter - 1) / shorter)
                         : std::max(width, height);
            auto decoded = platform_decode(source, info.format, max_side);
            rc = vips_thumbnail_image(
                    decoded.get(),
                    &out,
                    w,
                    "height",
                    h,
                    "size",
                    VIPS_SIZE_DOWN,
                    "crop",
                    crop ? VIPS_INTERESTING_CENTRE : VIPS_INTERESTING_NONE,
                    "output_profile",
                    "srgb",
                    nullptr);
        } else {
            VipsSource* vsrc = source_access::vips(source);
            if (vips_source_rewind(vsrc)) {
                source_access::rethrow_error(source);
                throw_vips_error("scaling: cannot rewind the source");
            }
            rc = vips_thumbnail_source(
                    vsrc,
                    &out,
                    w,
                    "height",
                    h,
                    "size",
                    VIPS_SIZE_DOWN,
                    "crop",
                    crop ? VIPS_INTERESTING_CENTRE : VIPS_INTERESTING_NONE,
                    "output_profile",
                    "srgb",
                    "option_string",
                    all_frames ? "n=-1" : "",
                    nullptr);
            source_access::rethrow_error(source);
        }
        if (rc)
            throw_vips_error("scaling failed");
        return image_ptr{out};
    }

    std::vector<std::byte> finish(image_ptr img, Backdrop backdrop, int quality) {
        if (vips_image_hasalpha(img.get()))
            img = backdrop == Backdrop::checkerboard ? over_checkerboard(img.get())
                                                     : over_white(img.get());
        return encode_jpeg(img.get(), quality);
    }

    std::optional<std::vector<std::byte>> thumbnail(
            Source& source, uint32_t edge, Backdrop backdrop) {
        auto info = probe(source);
        if (!info)
            return std::nullopt;
        edge = std::clamp(edge, min_thumbnail_edge, max_thumbnail_edge);
        uint32_t side = std::min({edge, info->width, info->height});
        if (!acceptable(*info, side, true))
            return std::nullopt;

        // libvips evaluates lazily, so a read of an encrypted source can fail anywhere from here
        // to the end of encoding; its own exception, rather than libvips' generic read error, is
        // what the caller needs.
        try {
            return finish(scaled(source, *info, side, side, true), backdrop, thumbnail_quality);
        } catch (...) {
            source_access::rethrow_error(source);
            throw;
        }
    }

}  // namespace detail

std::optional<std::vector<std::byte>> thumbnail(Source& source, uint32_t edge) {
    return detail::thumbnail(source, edge, detail::Backdrop::checkerboard);
}

std::optional<std::vector<std::byte>> thumbhash::of_picture(Source& source) {
    auto info = probe(source);
    if (!info)
        return std::nullopt;
    auto box = std::min(thumbhash::max_input_dimension, std::max(info->width, info->height));
    if (!detail::acceptable(*info, box, false))
        return std::nullopt;

    try {
        auto img = detail::to_srgb8(detail::scaled(source, *info, box, box, false).get());
        if (!vips_image_hasalpha(img.get())) {
            VipsImage* out;
            if (vips_addalpha(img.get(), &out, nullptr))
                detail::throw_vips_error("placeholder: adding alpha failed");
            img.reset(out);
        }
        size_t len = 0;
        std::unique_ptr<uint8_t, decltype(&g_free)> px{
                static_cast<uint8_t*>(vips_image_write_to_memory(img.get(), &len)), &g_free};
        if (!px)
            detail::throw_vips_error("placeholder: decoding failed");
        return thumbhash::encode(
                {reinterpret_cast<const std::byte*>(px.get()), len},
                static_cast<uint32_t>(img->Xsize),
                static_cast<uint32_t>(img->Ysize));
    } catch (...) {
        detail::source_access::rethrow_error(source);
        throw;
    }
}

}  // namespace session::image
