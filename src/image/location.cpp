#include "session/image/location.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

namespace session::image {

using namespace std::literals;

namespace {

    using mutable_bytes = std::span<std::byte>;
    using bytes = std::span<const std::byte>;

    uint8_t u8(bytes b, size_t at) {
        return static_cast<uint8_t>(b[at]);
    }

    bool has_at(bytes b, size_t at, std::string_view s) {
        return at <= b.size() && b.size() - at >= s.size() &&
               std::memcmp(b.data() + at, s.data(), s.size()) == 0;
    }

    std::string_view text_of(bytes b) {
        return {reinterpret_cast<const char*>(b.data()), b.size()};
    }

    uint32_t be16(bytes b, size_t at) {
        return (uint32_t{u8(b, at)} << 8) | u8(b, at + 1);
    }

    uint32_t be32(bytes b, size_t at) {
        return (be16(b, at) << 16) | be16(b, at + 2);
    }

    uint32_t le32(bytes b, size_t at) {
        return uint32_t{u8(b, at)} | (uint32_t{u8(b, at + 1)} << 8) |
               (uint32_t{u8(b, at + 2)} << 16) | (uint32_t{u8(b, at + 3)} << 24);
    }

    void put_be32(std::vector<std::byte>& out, uint32_t v) {
        for (int shift = 24; shift >= 0; shift -= 8)
            out.push_back(static_cast<std::byte>(v >> shift));
    }

    void put_le32(mutable_bytes b, size_t at, uint32_t v) {
        for (int i = 0; i < 4; i++)
            b[at + i] = static_cast<std::byte>(v >> (8 * i));
    }

    void zero(mutable_bytes b, size_t from, size_t to) {
        std::fill(b.begin() + from, b.begin() + to, std::byte{0});
    }

    // Matched as words anywhere in the packet: a false match costs only the XMP, never the picture.
    constexpr std::array PLACE_WORDS{"GPS"sv, "City"sv, "State"sv, "Country"sv, "Location"sv};

    bool names_a_place(std::string_view xmp) {
        return std::ranges::any_of(
                PLACE_WORDS, [xmp](std::string_view w) { return xmp.find(w) != xmp.npos; });
    }

    // MARK: EXIF

    enum class Exif { untouched, emptied, unreadable };

    // Bytes per value of each TIFF field type, by type number; 0 is a type TIFF does not define.
    constexpr std::array<uint8_t, 14> TIFF_TYPE_SIZE{0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4};

    constexpr uint32_t GPS_IFD_TAG = 0x8825;

    // Empties the GPS directory of a TIFF structure (EXIF's body) in place: its values and entries
    // become zeros and its count 0, which is a valid empty directory, so nothing else moves.
    Exif empty_gps(mutable_bytes tiff) {
        bool le;
        if (has_at(tiff, 0, "II"))
            le = true;
        else if (has_at(tiff, 0, "MM"))
            le = false;
        else
            return Exif::unreadable;

        auto fits = [&](uint64_t at, uint64_t n) {
            return at <= tiff.size() && n <= tiff.size() - at;
        };
        auto rd16 = [&](uint64_t at) -> std::optional<uint32_t> {
            if (!fits(at, 2))
                return std::nullopt;
            return le ? uint32_t{u8(tiff, at)} | (uint32_t{u8(tiff, at + 1)} << 8) : be16(tiff, at);
        };
        auto rd32 = [&](uint64_t at) -> std::optional<uint32_t> {
            if (!fits(at, 4))
                return std::nullopt;
            return le ? le32(tiff, at) : be32(tiff, at);
        };

        auto magic = rd16(2);
        auto ifd0 = rd32(4);
        if (magic != 42u || !ifd0)
            return Exif::unreadable;
        auto entries = rd16(*ifd0);
        if (!entries || !fits(*ifd0 + 2, uint64_t{12} * *entries))
            return Exif::unreadable;

        std::optional<uint32_t> gps;
        for (uint32_t i = 0; i < *entries; i++) {
            const uint64_t e = *ifd0 + 2 + uint64_t{12} * i;
            if (rd16(e) != GPS_IFD_TAG)
                continue;
            auto type = rd16(e + 2);
            if (rd32(e + 4) != 1u)
                return Exif::unreadable;
            gps = type == 3u ? rd16(e + 8) : rd32(e + 8);
            if (!gps)
                return Exif::unreadable;
            break;
        }
        if (!gps)
            return Exif::untouched;

        auto count = rd16(*gps);
        if (!count)
            return Exif::unreadable;
        if (*count == 0)
            return Exif::untouched;
        uint64_t end = *gps + 2 + uint64_t{12} * *count;
        if (end > tiff.size())
            return Exif::unreadable;

        for (uint32_t i = 0; i < *count; i++) {
            const uint64_t e = *gps + 2 + uint64_t{12} * i;
            auto type = *rd16(e + 2);
            auto n = *rd32(e + 4);
            if (type >= TIFF_TYPE_SIZE.size() || TIFF_TYPE_SIZE[type] == 0)
                return Exif::unreadable;
            const uint64_t size = uint64_t{TIFF_TYPE_SIZE[type]} * n;
            if (size <= 4)
                continue;  // held in the entry itself
            auto at = *rd32(e + 8);
            if (!fits(at, size))
                return Exif::unreadable;
            zero(tiff, at, at + size);
        }
        // The pointer to a next directory, which a GPS directory should not have.
        if (fits(end, 4))
            end += 4;
        zero(tiff, *gps, end);
        return Exif::emptied;
    }

    // EXIF as JPEG and WebP writers may prefix it.
    constexpr auto EXIF_PREFIX = "Exif\0\0"sv;

    Exif empty_gps_after_prefix(mutable_bytes data) {
        return empty_gps(has_at(data, 0, EXIF_PREFIX) ? data.subspan(EXIF_PREFIX.size()) : data);
    }

    // MARK: JPEG

    constexpr auto XMP_ID = "http://ns.adobe.com/xap/1.0/\0"sv;
    constexpr auto EXTENDED_XMP_ID = "http://ns.adobe.com/xmp/extension/\0"sv;
    // GUID, full length and offset, ahead of each extended XMP chunk.
    constexpr size_t EXTENDED_XMP_HEADER = 40;
    constexpr auto MPF_ID = "MPF\0"sv;
    constexpr uint32_t MP_ENTRY_TAG = 0xB002;
    constexpr size_t MP_ENTRY_SIZE = 16;

    constexpr uint8_t SOI = 0xD8, EOI = 0xD9, SOS = 0xDA, APP1 = 0xE1, APP2 = 0xE2, APP13 = 0xED,
                      COM = 0xFE;

    struct Segment {
        size_t marker;   // position of the marker byte, after its 0xFF
        size_t payload;  // first byte after the length
        size_t end;
    };

    struct Jpeg {
        mutable_bytes file;
        bool changed = false;

        // A comment of zeros, the same length: what a removed segment becomes, so that nothing
        // after it moves.
        void blank(const Segment& s) {
            file[s.marker] = std::byte{COM};
            zero(file, s.payload, s.end);
            changed = true;
        }

        // The picture starting at `start`, through its EOI.  Returns where it ends, and the
        // absolute positions of the other pictures its MPF index names.
        size_t picture(size_t start, std::vector<size_t>* others) {
            const size_t n = file.size();
            std::vector<Segment> xmp;
            std::string xmp_text;
            bool in_scan = false;
            size_t i = start + 2;
            size_t end = n;

            while (i < n) {
                if (u8(file, i) != 0xFF) {
                    if (!in_scan)
                        break;  // not a JPEG past here: leave the rest as it is
                    i++;
                    continue;
                }
                size_t m = i + 1;
                while (m < n && u8(file, m) == 0xFF)
                    m++;
                if (m >= n)
                    break;
                const uint8_t marker = u8(file, m);
                if (marker == EOI) {
                    end = m + 1;
                    break;
                }
                // Stuffed zeros, restarts and TEM carry no length.
                if (marker == 0x00 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
                    i = m + 1;
                    continue;
                }
                if (m + 3 > n)
                    break;
                const size_t len = be16(file, m + 1);
                if (len < 2 || m + 1 + len > n)
                    break;
                Segment s{m, m + 3, m + 1 + len};
                auto payload = mutable_bytes{file}.subspan(s.payload, s.end - s.payload);

                if (marker == APP1 && has_at(payload, 0, EXIF_PREFIX)) {
                    switch (empty_gps(payload.subspan(EXIF_PREFIX.size()))) {
                        case Exif::emptied: changed = true; break;
                        case Exif::unreadable: blank(s); break;
                        case Exif::untouched: break;
                    }
                } else if (marker == APP1 && has_at(payload, 0, XMP_ID)) {
                    xmp.push_back(s);
                    xmp_text += text_of(payload.subspan(XMP_ID.size()));
                } else if (marker == APP1 && has_at(payload, 0, EXTENDED_XMP_ID)) {
                    xmp.push_back(s);
                    if (payload.size() > EXTENDED_XMP_ID.size() + EXTENDED_XMP_HEADER)
                        xmp_text += text_of(
                                payload.subspan(EXTENDED_XMP_ID.size() + EXTENDED_XMP_HEADER));
                } else if (marker == APP13) {
                    blank(s);
                } else if (marker == APP2 && others && has_at(payload, 0, MPF_ID)) {
                    mp_index(payload.subspan(MPF_ID.size()), s.payload + MPF_ID.size(), *others);
                }

                in_scan = marker == SOS;
                i = s.end;
            }

            // Searched as one text: a GPS field can sit in the extended part, or straddle two.
            if (names_a_place(xmp_text))
                for (const auto& s : xmp)
                    blank(s);
            return end;
        }

        // The MPF index: a TIFF structure whose MP Entry field lists each picture's offset from the
        // index's own start.  The first picture, offset 0, is this one.
        void mp_index(bytes mp, size_t base, std::vector<size_t>& others) {
            bool le;
            if (has_at(mp, 0, "II"))
                le = true;
            else if (has_at(mp, 0, "MM"))
                le = false;
            else
                return;
            auto fits = [&](uint64_t at, uint64_t k) {
                return at <= mp.size() && k <= mp.size() - at;
            };
            auto rd16 = [&](uint64_t at) {
                return le ? uint32_t{u8(mp, at)} | (uint32_t{u8(mp, at + 1)} << 8) : be16(mp, at);
            };
            auto rd32 = [&](uint64_t at) { return le ? le32(mp, at) : be32(mp, at); };

            if (!fits(4, 4))
                return;
            const uint64_t ifd = rd32(4);
            if (!fits(ifd, 2))
                return;
            const uint32_t entries = rd16(ifd);
            if (!fits(ifd + 2, uint64_t{12} * entries))
                return;
            for (uint32_t i = 0; i < entries; i++) {
                const uint64_t e = ifd + 2 + uint64_t{12} * i;
                if (rd16(e) != MP_ENTRY_TAG)
                    continue;
                const uint64_t size = rd32(e + 4);
                const uint64_t at = rd32(e + 8);
                if (size < MP_ENTRY_SIZE || !fits(at, size))
                    return;
                for (uint64_t k = 0; k + MP_ENTRY_SIZE <= size; k += MP_ENTRY_SIZE)
                    if (auto offset = rd32(at + k + 8); offset != 0)
                        others.push_back(base + offset);
                return;
            }
        }
    };

    std::optional<std::vector<std::byte>> jpeg_without_location(bytes file) {
        std::vector<std::byte> out{file.begin(), file.end()};
        Jpeg jpeg{out};
        std::vector<size_t> others;
        const size_t first_end = jpeg.picture(0, &others);
        for (auto at : others)
            if (at >= first_end && at + 3 <= out.size() && u8(out, at) == 0xFF &&
                u8(out, at + 1) == SOI)
                jpeg.picture(at, nullptr);
        if (!jpeg.changed)
            return std::nullopt;
        return out;
    }

    // MARK: PNG

    constexpr auto PNG_SIGNATURE = "\x89PNG\r\n\x1a\n"sv;
    constexpr auto XMP_KEYWORD = "XML:com.adobe.xmp"sv;
    constexpr auto RAW_PROFILE_KEYWORD = "Raw profile type "sv;

    constexpr auto CRC_TABLE = [] {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }();

    uint32_t png_crc(bytes type_and_data) {
        uint32_t c = 0xFFFFFFFFu;
        for (auto b : type_and_data)
            c = CRC_TABLE[(c ^ static_cast<uint8_t>(b)) & 0xFF] ^ (c >> 8);
        return c ^ 0xFFFFFFFFu;
    }

    enum class Keep { as_is, changed, drop };

    // A text chunk's verdict.  `text` is what follows the keyword's NUL; null when it is compressed
    // and so cannot be searched.
    Keep text_chunk(std::string_view keyword, std::optional<std::string_view> text) {
        if (keyword.starts_with(RAW_PROFILE_KEYWORD))
            return Keep::drop;
        if (keyword != XMP_KEYWORD)
            return Keep::as_is;
        return !text || names_a_place(*text) ? Keep::drop : Keep::as_is;
    }

    Keep png_chunk(std::string_view type, mutable_bytes data) {
        if (type == "eXIf") {
            switch (empty_gps_after_prefix(data)) {
                case Exif::emptied: return Keep::changed;
                case Exif::unreadable: return Keep::drop;
                case Exif::untouched: return Keep::as_is;
            }
        }
        if (type != "tEXt" && type != "zTXt" && type != "iTXt")
            return Keep::as_is;

        const auto all = text_of(data);
        const auto nul = all.find('\0');
        if (nul == all.npos)
            return Keep::as_is;
        const auto keyword = all.substr(0, nul);
        auto rest = all.substr(nul + 1);
        if (type == "zTXt")
            return text_chunk(keyword, std::nullopt);
        if (type == "tEXt")
            return text_chunk(keyword, rest);

        // iTXt: compression flag, method, then language and translated keyword, each NUL-ended.
        if (rest.size() < 2)
            return text_chunk(keyword, std::nullopt);
        const bool compressed = rest[0] != '\0';
        rest.remove_prefix(2);
        for (int field = 0; field < 2; field++) {
            const auto end = rest.find('\0');
            if (end == rest.npos)
                return text_chunk(keyword, std::nullopt);
            rest.remove_prefix(end + 1);
        }
        return text_chunk(keyword, compressed ? std::nullopt : std::optional{rest});
    }

    std::optional<std::vector<std::byte>> png_without_location(bytes file) {
        std::vector<std::byte> out{file.begin(), file.begin() + PNG_SIGNATURE.size()};
        bool changed = false;
        size_t i = PNG_SIGNATURE.size();
        while (i < file.size()) {
            if (file.size() - i < 12 || be32(file, i) > file.size() - i - 12)
                break;
            const size_t len = be32(file, i);
            const auto type = text_of(file.subspan(i + 4, 4));
            std::vector<std::byte> data{file.begin() + i + 8, file.begin() + i + 8 + len};
            const size_t next = i + 12 + len;

            switch (png_chunk(type, data)) {
                case Keep::drop: changed = true; break;
                case Keep::as_is:
                    out.insert(out.end(), file.begin() + i, file.begin() + next);
                    break;
                case Keep::changed: {
                    changed = true;
                    const size_t at = out.size();
                    put_be32(out, static_cast<uint32_t>(len));
                    out.insert(out.end(), file.begin() + i + 4, file.begin() + i + 8);
                    out.insert(out.end(), data.begin(), data.end());
                    put_be32(out, png_crc(bytes{out}.subspan(at + 4)));
                    break;
                }
            }
            i = next;
            if (type == "IEND")
                break;
        }
        if (!changed)
            return std::nullopt;
        // Whatever follows IEND, or a chunk too short to be one, is kept as it was.
        out.insert(out.end(), file.begin() + i, file.end());
        return out;
    }

    // MARK: WebP

    constexpr uint8_t VP8X_XMP = 0x04, VP8X_EXIF = 0x08;
    constexpr size_t RIFF_HEADER = 12, CHUNK_HEADER = 8;

    std::optional<std::vector<std::byte>> webp_without_location(bytes file) {
        const size_t riff_end = std::min<size_t>(file.size(), uint64_t{le32(file, 4)} + 8);
        std::vector<std::byte> out{file.begin(), file.begin() + RIFF_HEADER};
        std::optional<size_t> vp8x;
        uint8_t cleared = 0;
        bool changed = false;

        size_t i = RIFF_HEADER;
        while (i < riff_end) {
            if (riff_end - i < CHUNK_HEADER)
                break;
            const size_t len = le32(file, i + 4);
            const size_t padded = len + (len & 1);
            if (padded > riff_end - i - CHUNK_HEADER)
                break;
            const auto fourcc = text_of(file.subspan(i, 4));
            const size_t next = i + CHUNK_HEADER + padded;
            std::vector<std::byte> chunk{file.begin() + i, file.begin() + next};
            auto data = mutable_bytes{chunk}.subspan(CHUNK_HEADER, len);

            bool keep = true;
            if (fourcc == "VP8X" && len >= 1)
                vp8x = out.size() + CHUNK_HEADER;
            else if (fourcc == "EXIF") {
                switch (empty_gps_after_prefix(data)) {
                    case Exif::emptied: changed = true; break;
                    case Exif::unreadable:
                        keep = false;
                        cleared |= VP8X_EXIF;
                        break;
                    case Exif::untouched: break;
                }
            } else if (fourcc == "XMP " && names_a_place(text_of(data))) {
                keep = false;
                cleared |= VP8X_XMP;
            }
            if (keep)
                out.insert(out.end(), chunk.begin(), chunk.end());
            else
                changed = true;
            i = next;
        }
        if (!changed)
            return std::nullopt;

        out.insert(out.end(), file.begin() + i, file.begin() + riff_end);
        if (vp8x)
            out[*vp8x] &= static_cast<std::byte>(~cleared);
        put_le32(out, 4, static_cast<uint32_t>(out.size() - 8));
        // Anything past the RIFF body is not part of the picture, and is kept as it was.
        out.insert(out.end(), file.begin() + riff_end, file.end());
        return out;
    }

    bool is_jpeg(bytes b) {
        return b.size() >= 3 && u8(b, 0) == 0xFF && u8(b, 1) == SOI && u8(b, 2) == 0xFF;
    }
    bool is_png(bytes b) {
        return has_at(b, 0, PNG_SIGNATURE);
    }
    bool is_webp(bytes b) {
        return has_at(b, 0, "RIFF") && has_at(b, 8, "WEBP");
    }

}  // namespace

bool may_carry_location(std::span<const std::byte> head) {
    return head.size() >= location_sniff_size && (is_jpeg(head) || is_png(head) || is_webp(head));
}

std::optional<std::vector<std::byte>> without_location(std::span<const std::byte> file) {
    if (!may_carry_location(file))
        return std::nullopt;
    if (is_jpeg(file))
        return jpeg_without_location(file);
    if (is_png(file))
        return png_without_location(file);
    return webp_without_location(file);
}

}  // namespace session::image
