#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
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

/// What sending a file does with it, as `send_plan` decides it.
enum class SendPlan {
    /// A picture this build decodes, re-encoded by `sendable`: nothing of the file but its picture
    /// goes.  Only doing it tells whether its pixels decode, and whether it then fits the size
    /// limit once scaled down as far as `sendable` goes; the send is refused if not.
    reencoded,
    /// Not a picture, and not labelled one: sent as it is.
    as_is,
    /// Sent as it is and flagged as the original file: a picture this build does not decode (HEIC
    /// off Apple, say), or a file labelled a picture that libvips does not read (TIFF, say).
    original_cannot_decode,
    /// Sent as it is and flagged as the original file: an animated PNG, which re-encoding would
    /// turn into a still (`Info::first_frame_only`).
    original_animated_png,
    /// Refused: a picture past the decode limits.
    too_large_to_decode,
    /// Refused: larger than the size limit once encrypted, and not a picture that re-encoding could
    /// shrink.
    too_large_for_server,
    /// Refused for now: a picture whose header is damaged, which is never sent as it is.
    unreadable,
    /// Refused: the file is not there, or is not a regular file.  Only `Client` says this.
    missing,
};

/// API: image/send_plan
///
/// What sending the file in `source` as an attachment, not marked as the original file, does with
/// it: decided from its header and nothing more, the same way the send itself decides.  Cheap
/// enough to ask while a user is still choosing files.
///
/// - `content_type`: what the file is labelled (`declares_image`); a file with none counts as not
///   labelled a picture.
/// - `max_encrypted_size`: the file server's limit on a file, which applies to what is uploaded: a
///   file sent as it is must be within it once encrypted (`attachment::encrypted_size`).
///
/// Throws std::runtime_error if reading the source fails, as `probe` does.
SendPlan send_plan(
        Source& source, std::optional<std::string_view> content_type, uint64_t max_encrypted_size);

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
