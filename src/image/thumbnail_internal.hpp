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
// checkerboard's cost; thumbnails and renditions are always made on the checkerboard.
enum class Backdrop { checkerboard, white };

std::optional<std::vector<std::byte>> thumbnail(Source& source, uint32_t edge, Backdrop backdrop);

// Shared by `thumbnail` and `rendition`, which differ only in how the picture is fitted.

// Whether a probed image is one we decode at all: decodable, within the pixel limits, and within
// `max_whole_decode_bytes` if its format decodes whole.
bool acceptable(const Info& info);

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

// `img` as 8-bit sRGB, converted from any embedded profile.
image_ptr to_srgb8(VipsImage* img);

// Transparency drawn over `backdrop`, encoded as a JPEG with no metadata.
std::vector<std::byte> finish(image_ptr img, Backdrop backdrop, int quality);

}  // namespace session::image::detail
