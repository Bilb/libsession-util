#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace session::image {

/// The fewest leading bytes `may_carry_location` needs to answer.
inline constexpr size_t location_sniff_size = 12;

/// API: image/may_carry_location
///
/// Whether a file starting with `head` is one `without_location` reads: JPEG, PNG or WebP, judged
/// by its signature rather than any declared type.  False for anything shorter than
/// `location_sniff_size`.
bool may_carry_location(std::span<const std::byte> head);

/// API: image/without_location
///
/// `file` with the metadata that can say where a picture was taken made unreadable, or nullopt
/// when it carries none, or is not a format read here.  The pixels are never touched: no decode,
/// no re-encode.
///
/// - The EXIF GPS directory is emptied in place, its values zeroed; every other EXIF field stays,
///   orientation included.  EXIF this cannot walk is removed whole, since nothing then shows it
///   holds no location.
/// - XMP that names a GPS field or a place (city, state, country, location) is removed, extended
///   XMP with it.  Other XMP stays: an HDR gain map is described there.
/// - JPEG only: every Photoshop resource block (APP13), where IPTC keeps its place fields.
/// - PNG only: ImageMagick's raw profile text chunks, which hold EXIF, IPTC or XMP as hex.
///
/// A JPEG keeps its length, a removed segment becoming a comment of zeros, so the offsets of a
/// multi-picture JPEG stay right; each picture after the first is treated the same.  A PNG or WebP
/// may come back shorter, with its chunk CRCs, RIFF size and feature flags kept consistent.
///
/// Not read: TIFF, HEIC, AVIF and GIF, which can hold the same metadata.
std::optional<std::vector<std::byte>> without_location(std::span<const std::byte> file);

}  // namespace session::image
