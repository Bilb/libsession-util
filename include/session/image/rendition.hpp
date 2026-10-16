#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "probe.hpp"
#include "source.hpp"

namespace session::image {

/// The range `rendition` clamps its `edge` to.  The top keeps a decoded rendition to 64 MiB
/// (4096² RGBA); the bottom is the least a viewer could call full screen.
inline constexpr uint32_t min_rendition_edge = 480;
inline constexpr uint32_t max_rendition_edge = 4096;

/// Raised with any change to `rendition`, or to the decoders it uses, that could make a rendition
/// of an image it refused before.  A caller that remembers refusals retries them once it changes.
inline constexpr int renderer_version = 2;

/// API: image/rendition
///
/// The whole picture in `source` re-encoded for showing it on a screen, as `sendable` makes a
/// picture for sending: scaled to fit inside an `edge` x `edge` box, where `edge` is clamped to
/// [`min_rendition_edge`, `max_rendition_edge`], and never enlarged.  What a viewer draws in place
/// of the original, whatever format that was; the original stays for export.
///
/// - EXIF orientation is applied, so the rendition is upright however the original was stored.
/// - A still picture without transparency is a jpegli JPEG; one with transparency, or an animation
///   with every frame and its delays, is a WebP.  The bytes say which.
/// - 8-bit sRGB at `thumbnail_quality`, with no metadata at all.
///
/// Returns nullopt for anything that is not an image we accept, under the same rules as
/// `thumbnail`, for an animation whose frames together exceed `max_total_pixels`, and for one
/// libvips decodes only the first frame of (`Info::first_frame_only`): a viewer draws the original.
/// The same image always gets the same answer from the same `renderer_version`.
///
/// Throws std::runtime_error as `thumbnail` does.
std::optional<std::vector<std::byte>> rendition(Source& source, uint32_t edge);

/// API: image/rendition_is_original
///
/// Whether the picture `probe` described as `info` is already what `rendition` would make for
/// `edge` in format and size: a JPEG or WebP `rendition` would accept, upright, 8 bits a sample,
/// no larger than the clamped edge.  What a picture sent by a client that re-encodes (`sendable`)
/// is, so a viewer can draw the original rather than a second copy of it.  Not checked: its colour
/// profile or metadata, which a viewer draws or ignores as it would the original's.
bool rendition_is_original(const Info& info, uint32_t edge);

}  // namespace session::image
