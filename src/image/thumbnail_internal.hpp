#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "session/image/probe.hpp"
#include "session/image/source.hpp"
#include "vips_internal.hpp"

namespace session::image::detail {

// What transparency is drawn over.  `white` exists for the benchmark that justifies the
// checkerboard's cost; thumbnails are always made on the checkerboard.
enum class Backdrop { checkerboard, white };

std::optional<std::vector<std::byte>> thumbnail(Source& source, uint32_t edge, Backdrop backdrop);

// Shared by `thumbnail`, `rendition` and `sendable`.

// Whether a probed image is one we decode at all: decodable, within the pixel limits, and within
// `max_whole_decode_bytes` if its format decodes whole, when `scaled` makes it `box` x `box`.
bool acceptable(const Info& info, uint32_t box, bool crop);

// The picture scaled to `width` x `height`: covering it and cropped to the centre when `crop`,
// else fitted inside it and never enlarged.  Orientation applied, converted to sRGB from any
// embedded profile.  The first frame only, unless `all_frames`, which keeps an animation's frames
// stacked as libvips holds them, with their delays.
image_ptr scaled(
        Source& source,
        const Info& info,
        uint32_t width,
        uint32_t height,
        bool crop,
        bool all_frames = false);

// A picture re-encoded whole from its pixels.
struct Reencoded {
    std::vector<std::byte> bytes;
    bool webp = false;
    uint32_t width = 0, height = 0, frames = 1;
};

// The picture fitted inside `box` x `box` (never enlarged): a jpegli JPEG when the decoded picture
// is still and has no alpha band, else a WebP with every frame and its delays.  `info` must pass
// `sendable_verdict`.
Reencoded reencode(Source& source, const Info& info, uint32_t box, int quality);

// `img` as 8-bit sRGB, converted from any embedded profile.
image_ptr to_srgb8(VipsImage* img);

// Transparency drawn over `backdrop`, encoded as a JPEG with no metadata.
std::vector<std::byte> finish(image_ptr img, Backdrop backdrop, int quality);

}  // namespace session::image::detail
