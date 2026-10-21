#pragma once

#include <algorithm>
#include <array>
#include <session/util.hpp>
#include <string_view>

namespace session::image {

/// The attachment content types Session treats as images: what a message may be shown as a gallery
/// of, what counts as an image in a conversation's preview, and what the `image_attachments`
/// auto-download mode fetches.  These are the formats the libvips loader whitelist accepts
/// (`allowed_loaders` in vips.hpp), and the two lists are to be kept in step.  Lowercase, and
/// compared against a content type's `mime_essence`.
///
/// HEIC/HEIF is deliberately absent even though some platforms can decode it: Session clients
/// convert HEIC to JPEG before sending, so one that arrives anyway is treated as a file.
///
/// `image/jpg` and `image/pjpeg` are not registered types, but are what some senders label JPEGs.
/// `image/apng` is absent, so is shown as a file; an animated PNG labelled `image/png` is shown as
/// a picture, from its first frame (`Info::first_frame_only`).
inline constexpr std::array<std::string_view, 7> displayable_image_types{
        "image/jpeg",
        "image/jpg",
        "image/pjpeg",
        "image/png",
        "image/webp",
        "image/gif",
        "image/avif",
};

/// The whitespace `mime_essence` trims: HTTP's, as the WHATWG MIME type parser has it.
inline constexpr std::string_view mime_whitespace = " \t\n\r";

/// API: image/mime_essence
///
/// `content_type` without its parameters or the whitespace around what is left, case kept:
/// `" IMAGE/PNG ; foo=bar"` gives `"IMAGE/PNG"`.  Empty when nothing is left.
constexpr std::string_view mime_essence(std::string_view content_type) {
    content_type = content_type.substr(0, content_type.find(';'));
    auto first = content_type.find_first_not_of(mime_whitespace);
    if (first == std::string_view::npos)
        return {};
    return content_type.substr(first, content_type.find_last_not_of(mime_whitespace) - first + 1);
}

/// API: image/is_displayable_image
///
/// Whether the `mime_essence` of `content_type` is one of `displayable_image_types`, ignoring ASCII
/// case: MIME types are case-insensitive, and a parameter such as `charset=binary` does not change
/// what the file is.  A content type is a sender's claim about a file, so this decides how an
/// attachment is presented, not whether its bytes are safe to decode; decoding enforces the loader
/// whitelist on the actual content.
constexpr bool is_displayable_image(std::string_view content_type) {
    auto essence = mime_essence(content_type);
    return std::ranges::any_of(displayable_image_types, [&](std::string_view type) {
        return string_iequal(essence, type);
    });
}

/// API: image/declares_image
///
/// Whether `content_type` says its file is a picture of any kind (`image/...`), displayable or not:
/// one that turns out not to be a picture libvips reads is sent as its original file rather than
/// as an ordinary one.
constexpr bool declares_image(std::string_view content_type) {
    return string_iequal(mime_essence(content_type).substr(0, 6), "image/");
}

}  // namespace session::image
