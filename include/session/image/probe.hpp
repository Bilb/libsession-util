#pragma once

#include <cstdint>
#include <optional>

#include "source.hpp"

namespace session::image {

/// The image formats Session accepts; see `allowed_loaders`.
enum class Format {
    jpeg,
    png,
    webp,
    gif,
    heic,  ///< HEIF with HEVC compression; see `Info::decodable`.
    avif,  ///< HEIF with AV1 compression.
};

/// The most pixels we decode in one frame: 16383², sharp's default and so what Session Desktop has
/// always been limited to.
inline constexpr uint64_t max_frame_pixels = 268'402'689;

/// The most pixels we decode across all the frames of an animation, when every frame is decoded
/// (a first-frame-only decode is bound by `max_frame_pixels` alone).  The same number, because it
/// is also sharp's limit when loading every frame, which is what Desktop's avatar handling does.
inline constexpr uint64_t max_total_pixels = max_frame_pixels;

/// What `probe()` reads from an image's header.
struct Info {
    Format format;

    /// One frame's size as displayed, i.e. after `orientation` is applied: a portrait photo
    /// stored sideways with orientation 6 reports its portrait width and height.
    uint32_t width;
    uint32_t height;

    /// 1 for a still image.  Always 1 for HEIC and AVIF: a HEIF file's other images are bursts,
    /// depth maps and the like rather than animation frames, and only its primary image is used.
    /// An animated PNG's is what its acTL chunk declares, capped at 65535; see `first_frame_only`.
    uint32_t frames;

    /// EXIF orientation, 1 to 8 (1 being upright).
    uint8_t orientation;

    bool has_alpha;

    /// Whether decoding holds a whole frame in memory, however small the result is to be: GIF,
    /// AVIF, progressive JPEG, interlaced PNG, animated WebP, and HEIC except on Apple platforms.
    /// The others stream or shrink as they decode, at a fraction of the memory.
    bool decoded_whole;

    /// Bits a sample takes once decoded: 8, or 16 for a 16-bit PNG and a HEIF of over 8 bits.
    uint8_t bits_per_sample;

    /// Whether this build can decode the image: `can_decode(format)`.
    bool decodable;

    /// The encoded size in bytes: Source::size().
    uint64_t size;

    /// Bands a decoded pixel has: 1 for grey, 3 for colour, 4 for CMYK or with alpha.
    uint8_t bands;

    /// What a progressive JPEG's decoder holds whatever size it decodes to: 128 bytes for every 8x8
    /// block of every component, at the resolution its frame header's sampling factors give it and
    /// padded to whole MCUs, as libjpeg allocates them.  0 for anything else.
    uint64_t coefficient_bytes;

    bool animated() const { return frames > 1; }

    /// An animation libvips decodes only the first frame of: an animated PNG (APNG), whatever its
    /// content type says.  That frame makes its thumbnail, but it is neither re-encoded to send nor
    /// given a rendition, which would turn the animation into a still.
    bool first_frame_only() const { return format == Format::png && animated(); }

    /// Whether decoding is within our pixel limits: `max_frame_pixels` for one frame, and also
    /// `max_total_pixels` across them when `all_frames` are to be decoded.
    bool within_pixel_limits(bool all_frames) const {
        uint64_t frame = uint64_t{width} * height;
        return frame <= max_frame_pixels && (!all_frames || frame * frames <= max_total_pixels);
    }
};

/// API: image/can_decode
///
/// Whether this build can decode images of `format`, e.g. for whether a file picker should offer
/// HEIC files.
///
/// HEIC is the one that varies.  libsession ships no HEVC decoder (the codec is patent-encumbered),
/// so HEIC decodes only through the platform's own decoder (ImageIO on Apple platforms) or through
/// a system libheif that has an HEVC decoder.  The other formats are always decodable, unless a
/// system libvips was built without them.
bool can_decode(Format format);

/// API: image/probe
///
/// Reads the header of the image in `source`, without decoding any pixels.  Reports oversized
/// images rather than refusing them (see `Info::within_pixel_limits`), since reading a header is
/// safe and a caller may want to say why an image cannot be used.
///
/// Returns nullopt if the source is not an image in a format we accept: anything the loader
/// whitelist refuses, and HEIF with a codec other than HEVC or AV1.
///
/// Throws std::runtime_error if reading the source fails, including an encrypted source that
/// turns out to be corrupt partway through: that is an error, not "not an image".
std::optional<Info> probe(Source& source);

/// API: image/recognized
///
/// Whether `source` is in a format `probe` accepts, judged from its first bytes without reading
/// its header: true for a picture whose header is then found damaged, which `probe` cannot tell
/// apart from one that is not a picture at all.
///
/// Throws std::runtime_error as `probe` does.
bool recognized(Source& source);

}  // namespace session::image
