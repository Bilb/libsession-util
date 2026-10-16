#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "source.hpp"

namespace session::image {

/// The longest edge a picture is sent at.  A larger one is scaled down; a smaller one is not
/// enlarged.
inline constexpr uint32_t sendable_edge = 2048;

/// The qualities tried, in order, before the picture is scaled down to fit.
inline constexpr std::array<int, 3> sendable_qualities{85, 75, 65};

/// The longest edge the fit stops at: a picture that does not fit at this size is not sent.
inline constexpr uint32_t min_sendable_edge = 320;

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
///   most `max_encrypted_size`; then the picture is scaled down by a fifth and tried again, down
///   to `min_sendable_edge`.
///
/// The same input gives the same bytes from the same build.
///
/// Returns nullopt when the picture does not fit even at `min_sendable_edge`.  Throws
/// std::runtime_error when it cannot be decoded: not a picture, a format this build does not
/// decode, over the decode limits, or damaged.
std::optional<Sendable> sendable(Source& source, size_t max_encrypted_size);

}  // namespace session::image
