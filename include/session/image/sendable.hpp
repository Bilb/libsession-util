#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "probe.hpp"
#include "source.hpp"

namespace session::image {

/// The longest edge a picture is sent at.  A larger one is scaled down; a smaller one is not
/// enlarged.
inline constexpr uint32_t sendable_edge = 2048;

/// The qualities tried, in order, before the picture is scaled down to fit.
inline constexpr std::array<int, 3> sendable_qualities{85, 75, 65};

/// The longest edge the fit stops at: a picture that does not fit at this size is not sent.
inline constexpr uint32_t min_sendable_edge = 320;

/// The most encodes the fit makes before giving up.
inline constexpr size_t max_sendable_attempts = 8;

/// What `sendable` can do with a picture, from its header alone.
enum class SendableVerdict {
    /// Re-encode it.
    encode,
    /// Not decode it at all: a format this build does not read (HEIC off Apple, say), or an
    /// animation it reads only the first frame of (`Info::first_frame_only`).
    cannot_decode,
    /// Decode it only past the decode limits `thumbnail` keeps to.
    too_large,
};

/// API: image/sendable_verdict
///
/// What `sendable` would do with the picture `probe` described as `info`.
SendableVerdict sendable_verdict(const Info& info);

/// A picture re-encoded for sending.
struct Sendable {
    std::vector<std::byte> bytes;
    /// `image/jpeg` or `image/webp`.
    std::string content_type;
    /// The upright size of one frame.
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t frames = 1;
};

/// API: image/sendable
///
/// The picture in `source` re-encoded from its pixels, so that nothing of the original file but
/// its picture survives: no EXIF, XMP, IPTC, ICC profile, maker note, embedded thumbnail or
/// trailing data.
///
/// - Orientation is applied and the colours converted to sRGB.
/// - At most `sendable_edge` on the longest side, never enlarged.
/// - A still picture without transparency is a jpegli JPEG; one with transparency, or an
///   animation (every frame, with its delays), is a WebP.
/// - Each of `sendable_qualities` is tried in turn until the encrypted size of the result is at
///   most `max_encrypted_size`; then the picture is scaled down, by how far the last try overshot,
///   and tried at the lowest quality, down to `min_sendable_edge` and at most
///   `max_sendable_attempts` encodes in all.
///
/// The same input gives the same bytes from the same build.
///
/// Returns nullopt when the picture does not fit within those tries.  Throws std::runtime_error for
/// a picture `sendable_verdict` does not say to encode, and for one that fails to decode or encode
/// (damaged, unreadable).
std::optional<Sendable> sendable(Source& source, size_t max_encrypted_size);

}  // namespace session::image
