#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "source.hpp"

namespace session::image {

/// The range `thumbnail` clamps its `edge` to.  The top keeps a decoded thumbnail to 4 MiB
/// (1024² RGBA), which is what makes it cheap enough to draw a screenful of.
inline constexpr uint32_t min_thumbnail_edge = 64;
inline constexpr uint32_t max_thumbnail_edge = 1024;

/// The most memory `thumbnail` lets decoding an image whole (`Info::decoded_whole`) take beyond
/// what a streaming decode of it would, estimated from its size at 6 to 27 bytes a pixel by format
/// and bit depth: an 8-bit AVIF of about 23 MP.  A progressive JPEG costs its
/// `Info::coefficient_bytes` plus what it decodes to, which shrinking on load cuts: a 4:2:0 photo
/// of about 58 MP at full size, about 115 MP for a thumbnail.  The streaming decode's own memory, a
/// few hundred MiB for a large photo across libvips' threads, is not counted.  Under
/// `max_frame_pixels` alone, a file of a few hundred bytes could take gigabytes.
inline constexpr uint64_t max_whole_decode_bytes = uint64_t{336} << 20;

/// The widest shape a thumbnail keeps, 21:9 either way up: a phone screenshot (about 9:19.5) stays
/// whole, while a panorama or a scrolling capture is cropped to its centre rather than fitted to a
/// sliver too thin to show anything.
inline constexpr uint32_t max_thumbnail_aspect_long = 21;
inline constexpr uint32_t max_thumbnail_aspect_short = 9;

/// The JPEG quality thumbnails are encoded at.
inline constexpr int thumbnail_quality = 90;

/// Raised with any change to `thumbnail`, or to the decoders it uses, that could make a thumbnail
/// of an image it refused before.  A caller that remembers refusals retries them once it changes.
inline constexpr int thumbnailer_version = 4;

/// API: image/thumbnail
///
/// A JPEG of the image in `source` in its own shape, for drawing it small: the image fitted inside
/// an `edge × edge` box, `edge` being clamped to [`min_thumbnail_edge`, `max_thumbnail_edge`].
/// Its longer side is `edge`, or the image's own longer side if that is smaller -- a thumbnail is
/// never larger than the picture it stands for, so an image smaller than `edge` gives a smaller
/// thumbnail rather than an upscaled one.
///
/// - An image wider than 21:9 either way up (`max_thumbnail_aspect_long`) is first cropped to its
///   centre at 21:9, so a panorama gives a strip that can still be drawn rather than a sliver.
///
/// - EXIF orientation is applied, so the thumbnail is upright however the original was stored.
/// - An animation gives its first frame.
/// - Transparency is drawn over a checkerboard of 8px squares, #FFFFFF and #CCCCCC, since JPEG has
///   no alpha: on a plain background a transparent image's subject can vanish into it.  The squares
///   are 8 thumbnail pixels whatever the image's size, being composited after the scaling.
/// - The result is 8-bit sRGB at `thumbnail_quality`, encoded with jpegli, and carries no metadata
///   at all.
///
/// Returns nullopt for anything that is not an image we accept: what `probe` refuses, a format
/// this build cannot decode (HEIC outside Apple platforms), an image over `max_frame_pixels`, and
/// one decoded whole that would take over `max_whole_decode_bytes`.  The same image always gets the
/// same answer from the same `thumbnailer_version`.
///
/// Throws std::runtime_error if the source cannot be read -- an encrypted source that turns out to
/// be corrupt, say -- or an image that probed as acceptable fails to decode, which may not happen
/// again: memory running short is one way.
std::optional<std::vector<std::byte>> thumbnail(Source& source, uint32_t edge);

}  // namespace session::image
