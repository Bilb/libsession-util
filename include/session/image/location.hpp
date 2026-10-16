#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace session::image {

/// How many leading bytes `may_carry_location` reads: a HEIF file's compatible brands can run
/// this far.  It answers from fewer, down to 12, for a file that short.
inline constexpr size_t location_sniff_size = 64;

/// API: image/may_carry_location
///
/// Whether a file starting with `head` is one `without_location` reads: JPEG, PNG, WebP, or a
/// HEIF picture (HEIC, AVIF), judged by its signature rather than any declared type.  False for
/// anything shorter than 12 bytes.
bool may_carry_location(std::span<const std::byte> head);

/// API: image/without_location
///
/// `file` with the metadata that can say where a picture was taken made unreadable, or nullopt
/// when it carries none, or is not a format read here.  The pixels are never touched: no decode,
/// no re-encode.
///
/// - Every EXIF GPS directory is emptied in place, its values zeroed; every other EXIF field
///   stays, orientation included.  EXIF whose GPS directory cannot be found is removed whole,
///   since nothing then shows it holds no location.
/// - XMP with a property holding a position or a place (GPS fields, coordinates, city, state,
///   country, location) is removed; names are matched in any case.  Other XMP stays: an HDR gain
///   map is described there.  XMP held inside EXIF is treated the same, and IPTC held there is
///   always zeroed.
/// - Every C2PA manifest is removed: it can hold a location no search finds, and no longer
///   verifies against a file this changed.
/// - JPEG: every Photoshop resource block (APP13), where IPTC keeps its place fields.  Anything
///   after the last picture is cut, which is where a motion photo keeps its video, together with
///   the XMP that points at it.
/// - PNG: ImageMagick's raw profile text chunks, which hold EXIF, IPTC or XMP as hex.
///
/// A removed JPEG segment becomes a comment of zeros, and HEIF items are blanked where they lie,
/// so the offsets inside both formats stay right.  A PNG or WebP may come back shorter, with its
/// chunk CRCs, RIFF size and feature flags kept consistent.
///
/// Not read: TIFF and GIF, which can hold the same metadata; the tracks of a HEIF sequence.
///
/// Throws std::runtime_error for a HEIF metadata item stored where this cannot follow, by
/// reference to another item or in another file, rather than say there is nothing to remove.
std::optional<std::vector<std::byte>> without_location(std::span<const std::byte> file);

}  // namespace session::image
