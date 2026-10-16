#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "source.hpp"

namespace session::image {

/// The range `rendition` clamps its `edge` to.  The top keeps a decoded rendition to 64 MiB
/// (4096² RGBA); the bottom is the least a viewer could call full screen.
inline constexpr uint32_t min_rendition_edge = 480;
inline constexpr uint32_t max_rendition_edge = 4096;

/// Raised with any change to `rendition`, or to the decoders it uses, that could make a rendition
/// of an image it refused before.  A caller that remembers refusals retries them once it changes.
inline constexpr int renderer_version = 1;

/// API: image/rendition
///
/// A JPEG of the whole picture in `source`, for showing it on a screen: scaled to fit inside an
/// `edge` x `edge` box, where `edge` is clamped to [`min_rendition_edge`, `max_rendition_edge`],
/// and never enlarged -- a picture smaller than the box gives itself at its own size.  What a
/// viewer draws in place of the original, whatever format that was.
///
/// - EXIF orientation is applied, so the rendition is upright however the original was stored.
/// - An animation gives its first frame.
/// - Transparency is drawn over the checkerboard `thumbnail` uses, since JPEG has no alpha.
/// - The result is 8-bit sRGB at `thumbnail_quality`, encoded with jpegli, and carries no metadata
///   at all.
///
/// Returns nullopt for anything that is not an image we accept, under the same rules as
/// `thumbnail`.  The same image always gets the same answer from the same `renderer_version`.
///
/// Throws std::runtime_error as `thumbnail` does.
std::optional<std::vector<std::byte>> rendition(Source& source, uint32_t edge);

}  // namespace session::image
