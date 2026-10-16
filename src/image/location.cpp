#include "session/image/location.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace session::image {

using namespace std::literals;

// Every position and length below is a uint64_t: they add untrusted 32-bit fields, which would
// wrap a 32-bit size_t.

namespace {

    using mutable_bytes = std::span<std::byte>;
    using bytes = std::span<const std::byte>;

    bool fits(bytes b, uint64_t at, uint64_t n) {
        return at <= b.size() && n <= b.size() - at;
    }

    uint8_t u8(bytes b, uint64_t at) {
        return static_cast<uint8_t>(b[at]);
    }

    bool has_at(bytes b, uint64_t at, std::string_view s) {
        return fits(b, at, s.size()) && std::memcmp(b.data() + at, s.data(), s.size()) == 0;
    }

    std::string_view text_of(bytes b) {
        return {reinterpret_cast<const char*>(b.data()), b.size()};
    }

    uint32_t be16(bytes b, uint64_t at) {
        return (uint32_t{u8(b, at)} << 8) | u8(b, at + 1);
    }

    uint32_t be32(bytes b, uint64_t at) {
        return (be16(b, at) << 16) | be16(b, at + 2);
    }

    uint64_t be64(bytes b, uint64_t at) {
        return (uint64_t{be32(b, at)} << 32) | be32(b, at + 4);
    }

    uint32_t le32(bytes b, uint64_t at) {
        return uint32_t{u8(b, at)} | (uint32_t{u8(b, at + 1)} << 8) |
               (uint32_t{u8(b, at + 2)} << 16) | (uint32_t{u8(b, at + 3)} << 24);
    }

    // A big-endian unsigned of `n` bytes, n in [0, 8].
    uint64_t be_n(bytes b, uint64_t at, unsigned n) {
        uint64_t v = 0;
        for (unsigned i = 0; i < n; i++)
            v = (v << 8) | u8(b, at + i);
        return v;
    }

    void put_be32(mutable_bytes b, uint64_t at, uint32_t v) {
        for (int i = 0; i < 4; i++)
            b[at + i] = static_cast<std::byte>(v >> (24 - 8 * i));
    }

    void put_le32(mutable_bytes b, uint64_t at, uint32_t v) {
        for (int i = 0; i < 4; i++)
            b[at + i] = static_cast<std::byte>(v >> (8 * i));
    }

    void fill(mutable_bytes b, uint64_t from, uint64_t to, std::byte with = std::byte{0}) {
        std::fill(b.begin() + from, b.begin() + to, with);
    }

    // Lowercased, with NULs dropped so that UTF-16 XMP reads as its ASCII.
    std::string folded(std::string_view text) {
        std::string out;
        out.reserve(text.size());
        for (char c : text)
            if (c != '\0')
                out.push_back(c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c);
        return out;
    }

    bool mentions(std::string_view text, std::span<const std::string_view> words) {
        const auto f = folded(text);
        return std::ranges::any_of(words, [&f](std::string_view w) { return f.find(w) != f.npos; });
    }

    bool is_name_char(char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
    }

    // Whether an XMP property's local name, lowercased, is one that holds a position or a place.
    bool is_place_property(std::string_view name) {
        constexpr std::array exact{
                "city"sv, "state"sv, "provincestate"sv, "worldregion"sv, "countryname"sv};
        constexpr std::array within{"latitude"sv, "longitude"sv, "altitude"sv, "location"sv};
        return name.starts_with("gps") || name.starts_with("country") ||
               std::ranges::find(exact, name) != exact.end() ||
               std::ranges::any_of(
                       within, [&](std::string_view w) { return name.find(w) != name.npos; });
    }

    // Any property named `prefix:local` whose local name holds a place, in any case.  Names, not
    // substrings: `hdrgm:HDRCapacityMax` describes a gain map, and says nothing of a city.
    bool names_a_place(std::string_view text) {
        const auto f = folded(text);
        for (size_t colon = f.find(':'); colon != f.npos; colon = f.find(':', colon + 1)) {
            size_t end = colon + 1;
            while (end < f.size() && is_name_char(f[end]))
                end++;
            if (is_place_property(std::string_view{f}.substr(colon + 1, end - colon - 1)))
                return true;
        }
        return false;
    }

    // What a motion photo's XMP says about the video kept after the picture.
    constexpr std::array CONTAINER_WORDS{"container:directory"sv, "microvideo"sv, "motionphoto"sv};

    // MARK: EXIF

    enum class Exif { untouched, emptied, unreadable };

    // Bytes per value of each TIFF field type, by type number; 0 is a type TIFF does not define.
    constexpr std::array<uint8_t, 14> TIFF_TYPE_SIZE{0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4};

    constexpr uint32_t GPS_IFD_TAG = 0x8825, XMP_TAG = 0x02BC, IPTC_TAG = 0x83BB;

    // Empties every GPS directory IFD0 points at, in place: values and entries become zeros and
    // the count 0, which is a valid empty directory, so nothing else in the structure moves.  The
    // XMP IFD0 holds is zeroed when it names a place, and its IPTC, binary place fields and all,
    // always.
    Exif empty_gps(mutable_bytes tiff) {
        bool le;
        if (has_at(tiff, 0, "II"))
            le = true;
        else if (has_at(tiff, 0, "MM"))
            le = false;
        else
            return Exif::unreadable;

        auto rd16 = [&](uint64_t at) -> std::optional<uint32_t> {
            if (!fits(tiff, at, 2))
                return std::nullopt;
            return le ? uint32_t{u8(tiff, at)} | (uint32_t{u8(tiff, at + 1)} << 8) : be16(tiff, at);
        };
        auto rd32 = [&](uint64_t at) -> std::optional<uint32_t> {
            if (!fits(tiff, at, 4))
                return std::nullopt;
            return le ? le32(tiff, at) : be32(tiff, at);
        };

        auto magic = rd16(2);
        auto ifd0 = rd32(4);
        if (magic != 42u || !ifd0)
            return Exif::unreadable;
        auto entries = rd16(*ifd0);
        if (!entries || !fits(tiff, uint64_t{*ifd0} + 2, uint64_t{12} * *entries))
            return Exif::unreadable;

        bool emptied = false;
        for (uint32_t i = 0; i < *entries; i++) {
            const uint64_t e = uint64_t{*ifd0} + 2 + uint64_t{12} * i;
            const auto tag = *rd16(e);
            if (tag == XMP_TAG || tag == IPTC_TAG) {
                const auto type = *rd16(e + 2);
                if (type >= TIFF_TYPE_SIZE.size())
                    continue;
                const uint64_t size = uint64_t{TIFF_TYPE_SIZE[type]} * *rd32(e + 4);
                const uint64_t at = size <= 4 ? e + 8 : *rd32(e + 8);
                if (!fits(tiff, at, size))
                    continue;
                auto value = tiff.subspan(at, size);
                if (std::ranges::all_of(value, [](std::byte b) { return b == std::byte{0}; }))
                    continue;
                if (tag == IPTC_TAG || names_a_place(text_of(value))) {
                    fill(tiff, at, at + size);
                    emptied = true;
                }
                continue;
            }
            if (tag != GPS_IFD_TAG)
                continue;
            const auto type = *rd16(e + 2);
            if (rd32(e + 4) != 1u || (type != 3 && type != 4 && type != 13))
                return Exif::unreadable;
            const uint64_t gps = type == 3 ? *rd16(e + 8) : *rd32(e + 8);
            auto count = rd16(gps);
            if (!count || !fits(tiff, gps + 2, uint64_t{12} * *count))
                return Exif::unreadable;
            if (*count == 0)
                continue;

            for (uint32_t k = 0; k < *count; k++) {
                const uint64_t g = gps + 2 + uint64_t{12} * k;
                const auto field = *rd16(g + 2);
                if (field >= TIFF_TYPE_SIZE.size())
                    continue;  // no value TIFF defines, so nothing a reader would find
                const uint64_t size = uint64_t{TIFF_TYPE_SIZE[field]} * *rd32(g + 4);
                if (size <= 4)
                    continue;  // held in the entry itself
                // A value outside the structure is not in the file to remove.
                if (const uint64_t at = *rd32(g + 8); fits(tiff, at, size))
                    fill(tiff, at, at + size);
            }
            uint64_t end = gps + 2 + uint64_t{12} * *count;
            // The pointer to a next directory, which a GPS directory should not have.
            if (fits(tiff, end, 4))
                end += 4;
            fill(tiff, gps, end);
            emptied = true;
        }
        return emptied ? Exif::emptied : Exif::untouched;
    }

    // EXIF as JPEG and WebP writers may prefix it.
    constexpr auto EXIF_PREFIX = "Exif\0\0"sv;

    Exif empty_gps_after_prefix(mutable_bytes data) {
        return empty_gps(has_at(data, 0, EXIF_PREFIX) ? data.subspan(EXIF_PREFIX.size()) : data);
    }

    // MARK: JPEG

    constexpr auto XMP_ID = "http://ns.adobe.com/xap/1.0/\0"sv;
    constexpr auto EXTENDED_XMP_ID = "http://ns.adobe.com/xmp/extension/\0"sv;
    // GUID (32), full length (4) and this chunk's offset (4), ahead of each extended XMP chunk.
    constexpr size_t EXTENDED_XMP_HEADER = 40;
    constexpr auto MPF_ID = "MPF\0"sv;
    constexpr uint32_t MP_ENTRY_TAG = 0xB002;
    constexpr size_t MP_ENTRY_SIZE = 16;

    constexpr uint8_t SOI = 0xD8, EOI = 0xD9, SOS = 0xDA, APP1 = 0xE1, APP2 = 0xE2, APP11 = 0xEB,
                      APP13 = 0xED, COM = 0xFE;

    struct Segment {
        uint64_t marker;   // position of the marker byte, after its 0xFF
        uint64_t payload;  // first byte after the length
        uint64_t end;
    };

    struct Jpeg {
        mutable_bytes file;
        bool changed = false;
        std::vector<Segment> c2pa;           // APP11
        std::vector<Segment> container_xmp;  // XMP pointing past the last picture
        std::vector<uint64_t> others;        // pictures the first one's MPF index names

        // A comment of zeros, the same length: what a removed segment becomes, so that nothing
        // after it moves.
        void blank(const Segment& s) {
            file[s.marker] = std::byte{COM};
            fill(file, s.payload, s.end);
            changed = true;
        }

        bytes payload(const Segment& s) const {
            return bytes{file}.subspan(s.payload, s.end - s.payload);
        }

        // The picture starting at `start`, through its EOI.  Returns where it ends: the file's
        // end when it does not, so nothing after a damaged picture is mistaken for a trailer.
        uint64_t picture(uint64_t start, bool first) {
            const uint64_t n = file.size();
            std::vector<Segment> xmp;
            std::string xmp_text;
            std::vector<std::pair<uint32_t, Segment>> extended;
            bool in_scan = false;
            uint64_t i = start + 2;
            uint64_t end = n;

            while (i < n) {
                // Outside a scan this is padding a decoder skips over too.
                if (u8(file, i) != 0xFF) {
                    i++;
                    continue;
                }
                uint64_t m = i + 1;
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
                // A picture with no EOI, and another after it: a decoder stops here too.
                if (in_scan && marker == SOI) {
                    end = i;
                    break;
                }
                if (!fits(file, m + 1, 2))
                    break;
                const uint64_t len = be16(file, m + 1);
                if (len < 2 || !fits(file, m + 1, len))
                    break;
                const Segment s{m, m + 3, m + 1 + len};
                auto data = file.subspan(s.payload, s.end - s.payload);

                if (marker == APP1 && has_at(data, 0, EXIF_PREFIX)) {
                    switch (empty_gps(data.subspan(EXIF_PREFIX.size()))) {
                        case Exif::emptied: changed = true; break;
                        case Exif::unreadable: blank(s); break;
                        case Exif::untouched: break;
                    }
                } else if (marker == APP1 && has_at(data, 0, XMP_ID)) {
                    xmp.push_back(s);
                    xmp_text += text_of(data.subspan(XMP_ID.size()));
                } else if (marker == APP1 && has_at(data, 0, EXTENDED_XMP_ID)) {
                    xmp.push_back(s);
                    const uint64_t header = EXTENDED_XMP_ID.size() + EXTENDED_XMP_HEADER;
                    if (data.size() >= header)
                        extended.emplace_back(be32(data, header - 4), s);
                } else if (marker == APP13) {
                    blank(s);
                } else if (marker == APP11) {
                    c2pa.push_back(s);
                } else if (marker == APP2 && first && has_at(data, 0, MPF_ID)) {
                    mp_index(data.subspan(MPF_ID.size()), s.payload + MPF_ID.size());
                }

                in_scan = marker == SOS;
                i = s.end;
            }

            // In the order of their offsets, as one text: a field can straddle two chunks.
            std::ranges::stable_sort(extended, {}, &std::pair<uint32_t, Segment>::first);
            const uint64_t header = EXTENDED_XMP_ID.size() + EXTENDED_XMP_HEADER;
            for (const auto& [offset, s] : extended)
                xmp_text += text_of(payload(s).subspan(header));

            if (names_a_place(xmp_text)) {
                for (const auto& s : xmp)
                    blank(s);
            } else if (first && mentions(xmp_text, CONTAINER_WORDS)) {
                container_xmp = xmp;
            }
            return end;
        }

        // The MPF index: a TIFF structure whose MP Entry field lists each picture's offset from the
        // index's own start.  The first picture, offset 0, is this one.
        void mp_index(bytes mp, uint64_t base) {
            bool le;
            if (has_at(mp, 0, "II"))
                le = true;
            else if (has_at(mp, 0, "MM"))
                le = false;
            else
                return;
            auto rd16 = [&](uint64_t at) {
                return le ? uint32_t{u8(mp, at)} | (uint32_t{u8(mp, at + 1)} << 8) : be16(mp, at);
            };
            auto rd32 = [&](uint64_t at) { return le ? le32(mp, at) : be32(mp, at); };

            if (!fits(mp, 4, 4))
                return;
            const uint64_t ifd = rd32(4);
            if (!fits(mp, ifd, 2))
                return;
            const uint32_t entries = rd16(ifd);
            if (!fits(mp, ifd + 2, uint64_t{12} * entries))
                return;
            for (uint32_t i = 0; i < entries; i++) {
                const uint64_t e = ifd + 2 + uint64_t{12} * i;
                if (rd16(e) != MP_ENTRY_TAG)
                    continue;
                const uint64_t size = rd32(e + 4);
                const uint64_t at = rd32(e + 8);
                if (!fits(mp, at, size))
                    return;
                for (uint64_t k = 0; k + MP_ENTRY_SIZE <= size; k += MP_ENTRY_SIZE)
                    if (const uint64_t offset = rd32(at + k + 8); offset != 0)
                        others.push_back(base + offset);
                return;
            }
        }
    };

    // More than any multi-picture JPEG holds: a gain map, a depth map, a few previews.
    constexpr size_t MAX_PICTURES = 16;

    std::optional<std::vector<std::byte>> jpeg_without_location(bytes file) {
        std::vector<std::byte> out{file.begin(), file.end()};
        Jpeg jpeg{out};
        uint64_t last = jpeg.picture(0, true);
        std::ranges::sort(jpeg.others);
        size_t read = 0;
        for (auto at : jpeg.others) {
            // In order, so one already read is skipped rather than walked again.
            if (at < last || read == MAX_PICTURES || !fits(out, at, 3) || u8(out, at) != 0xFF ||
                u8(out, at + 1) != SOI)
                continue;
            last = jpeg.picture(at, false);
            read++;
        }

        const bool trailer = last < out.size();
        // Zeros after the last picture point nowhere, so the XMP describing it can stay.
        if (trailer && std::any_of(out.begin() + last, out.end(), [](std::byte b) {
                return b != std::byte{0};
            }))
            for (const auto& s : jpeg.container_xmp)
                jpeg.blank(s);

        // C2PA can hold a location in forms no text search finds (compressed boxes, ingredient
        // thumbnails), and a manifest kept on a file this may change no longer verifies anyway.
        for (const auto& s : jpeg.c2pa)
            jpeg.blank(s);

        if (!jpeg.changed && !trailer)
            return std::nullopt;
        out.resize(last);
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

    // A text chunk's verdict.  `text` is what follows the keyword; null when it is compressed and
    // so cannot be searched.
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
        std::vector<std::byte> out;
        out.reserve(file.size());
        out.insert(out.end(), file.begin(), file.begin() + PNG_SIGNATURE.size());
        bool changed = false;

        uint64_t i = PNG_SIGNATURE.size();
        while (fits(file, i, 12)) {
            const uint64_t len = be32(file, i);
            if (!fits(file, i + 12, len))
                break;
            const uint64_t next = i + 12 + len;
            const uint64_t at = out.size();
            out.insert(out.end(), file.begin() + i, file.begin() + next);
            // A copy: the chunk it names may be dropped from `out` below.
            const std::string type{text_of(bytes{out}.subspan(at + 4, 4))};
            auto data = mutable_bytes{out}.subspan(at + 8, len);

            // C2PA, for the reasons the JPEG reader drops it.
            switch (type == "caBX" ? Keep::drop : png_chunk(type, data)) {
                case Keep::as_is: break;
                case Keep::drop:
                    out.resize(at);
                    changed = true;
                    break;
                case Keep::changed:
                    put_be32(out, at + 8 + len, png_crc(bytes{out}.subspan(at + 4, len + 4)));
                    changed = true;
                    break;
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
    constexpr uint64_t RIFF_HEADER = 12, CHUNK_HEADER = 8;

    std::optional<std::vector<std::byte>> webp_without_location(bytes file) {
        const uint64_t riff_end = std::min<uint64_t>(file.size(), uint64_t{le32(file, 4)} + 8);
        std::vector<std::byte> out;
        out.reserve(file.size());
        out.insert(out.end(), file.begin(), file.begin() + RIFF_HEADER);
        bool changed = false, exif_kept = false, xmp_kept = false;

        uint64_t i = RIFF_HEADER;
        while (i < riff_end && riff_end - i >= CHUNK_HEADER) {
            const uint64_t len = le32(file, i + 4);
            const uint64_t padded = len + (len & 1);
            if (padded > riff_end - i - CHUNK_HEADER)
                break;
            const uint64_t next = i + CHUNK_HEADER + padded;
            const uint64_t at = out.size();
            out.insert(out.end(), file.begin() + i, file.begin() + next);
            const auto fourcc = text_of(bytes{out}.subspan(at, 4));
            auto data = mutable_bytes{out}.subspan(at + CHUNK_HEADER, len);

            bool keep = true;
            if (fourcc == "EXIF") {
                switch (empty_gps_after_prefix(data)) {
                    case Exif::emptied: changed = true; break;
                    case Exif::unreadable: keep = false; break;
                    case Exif::untouched: break;
                }
                exif_kept |= keep;
            } else if (fourcc == "XMP ") {
                keep = !names_a_place(text_of(data));
                xmp_kept |= keep;
            } else if (fourcc == "C2PA") {
                keep = false;  // for the reasons the JPEG reader drops it
            }
            if (!keep) {
                out.resize(at);
                changed = true;
            }
            i = next;
        }
        if (!changed)
            return std::nullopt;

        out.insert(out.end(), file.begin() + i, file.begin() + riff_end);
        // VP8X is the first chunk when there is one; a file with it elsewhere keeps its flags.
        if (has_at(out, RIFF_HEADER, "VP8X") && fits(out, RIFF_HEADER + CHUNK_HEADER, 1)) {
            auto& flags = out[RIFF_HEADER + CHUNK_HEADER];
            if (!exif_kept)
                flags &= static_cast<std::byte>(~VP8X_EXIF);
            if (!xmp_kept)
                flags &= static_cast<std::byte>(~VP8X_XMP);
        }
        put_le32(out, 4, static_cast<uint32_t>(out.size() - 8));
        // Anything past the RIFF body is not part of the picture, and is kept as it was.
        out.insert(out.end(), file.begin() + riff_end, file.end());
        return out;
    }

    // MARK: HEIF

    struct Box {
        std::string_view type;
        uint64_t body;  // first byte after the header
        uint64_t end;
    };

    // The boxes laid end to end in [from, to).
    std::vector<Box> boxes(bytes b, uint64_t from, uint64_t to) {
        std::vector<Box> out;
        while (to - from >= 8) {
            uint64_t size = be32(b, from);
            uint64_t header = 8;
            if (size == 1) {
                if (to - from < 16)
                    break;
                size = be64(b, from + 8);
                header = 16;
            } else if (size == 0) {
                size = to - from;
            }
            if (size < header || size > to - from)
                break;
            out.push_back({text_of(b.subspan(from + 4, 4)), from + header, from + size});
            from += size;
        }
        return out;
    }

    struct Item {
        uint32_t id;
        bool exif;  // else XMP
    };

    // The Exif and XMP items an `iinf` box lists.
    std::vector<Item> metadata_items(bytes b, const Box& iinf) {
        std::vector<Item> items;
        if (iinf.end - iinf.body < 6)
            return items;
        const unsigned version = u8(b, iinf.body);
        const uint64_t first = iinf.body + 4 + (version == 0 ? 2 : 4);
        if (first > iinf.end)
            return items;
        for (const auto& infe : boxes(b, first, iinf.end)) {
            if (infe.type != "infe" || infe.end - infe.body < 4)
                continue;
            const unsigned v = u8(b, infe.body);
            if (v < 2)
                continue;
            const uint64_t id_size = v == 2 ? 2 : 4;
            const uint64_t type_at = infe.body + 4 + id_size + 2;
            if (type_at + 4 > infe.end)
                continue;
            const uint32_t id = static_cast<uint32_t>(be_n(b, infe.body + 4, id_size));
            const auto type = text_of(b.subspan(type_at, 4));
            if (type == "Exif") {
                items.push_back({id, true});
            } else if (type == "mime") {
                // Item name, then content type, each NUL-ended.
                auto rest = text_of(b.subspan(type_at + 4, infe.end - type_at - 4));
                const auto name_end = rest.find('\0');
                if (name_end == rest.npos)
                    continue;
                const auto content_type = folded(rest.substr(name_end + 1));
                if (content_type.find("rdf+xml") != content_type.npos ||
                    content_type.find("xmp") != content_type.npos)
                    items.push_back({id, false});
            }
        }
        return items;
    }

    struct Extents {
        bool located = true;  // false for an item stored where this cannot follow
        std::vector<std::pair<uint64_t, uint64_t>> spans;  // [offset, offset + length)
    };

    // Every item's extents from `iloc`, in the file body or in `idat` (construction methods 0 and
    // 1); an item stored by reference to another item, or in another file, is not located.
    std::map<uint64_t, Extents> item_locations(bytes b, const Box& iloc, const Box* idat) {
        std::map<uint64_t, Extents> out;
        uint64_t p = iloc.body;
        auto need = [&](uint64_t n) { return n <= iloc.end - p; };
        if (!need(6))
            return out;
        const unsigned version = u8(b, p);
        const unsigned offset_size = u8(b, p + 4) >> 4, length_size = u8(b, p + 4) & 0xF;
        const unsigned base_size = u8(b, p + 5) >> 4;
        const unsigned index_size = (version == 1 || version == 2) ? (u8(b, p + 5) & 0xF) : 0;
        if (version > 2 || offset_size > 8 || length_size > 8 || base_size > 8 || index_size > 8)
            return out;
        p += 6;
        const unsigned count_size = version < 2 ? 2 : 4;
        if (!need(count_size))
            return out;
        const uint64_t count = be_n(b, p, count_size);
        p += count_size;

        for (uint64_t k = 0; k < count; k++) {
            const unsigned id_size = version < 2 ? 2 : 4;
            if (!need(id_size))
                break;
            const uint64_t id = be_n(b, p, id_size);
            p += id_size;
            unsigned method = 0;
            if (version == 1 || version == 2) {
                if (!need(2))
                    break;
                method = be16(b, p) & 0xF;
                p += 2;
            }
            if (!need(2 + base_size + 2))
                break;
            const uint64_t reference = be16(b, p);
            const uint64_t base = be_n(b, p + 2, base_size);
            const uint64_t extents = be16(b, p + 2 + base_size);
            p += 2 + base_size + 2;
            const uint64_t extent_size = uint64_t{index_size} + offset_size + length_size;
            if (extent_size * extents > iloc.end - p)
                break;

            auto& item = out[id];
            // Where offsets count from, and how far they may reach.
            uint64_t from = 0, to = b.size();
            if (method == 1 && idat) {
                from = idat->body;
                to = idat->end;
            }
            item.located = reference == 0 && (method == 0 || (method == 1 && idat));
            for (uint64_t x = 0; item.located && x < extents; x++) {
                const uint64_t e = p + extent_size * x + index_size;
                const uint64_t offset = base + be_n(b, e, offset_size);
                uint64_t length = be_n(b, e + offset_size, length_size);
                if (offset > to - from)
                    continue;
                if (length == 0 || length > to - from - offset)
                    length = to - from - offset;
                item.spans.emplace_back(from + offset, length);
            }
            p += extent_size * extents;
        }
        return out;
    }

    std::optional<std::vector<std::byte>> heif_without_location(bytes file) {
        std::vector<std::byte> out{file.begin(), file.end()};
        bool changed = false;
        for (const auto& meta : boxes(out, 0, out.size())) {
            if (meta.type != "meta" || meta.end - meta.body < 4)
                continue;
            const auto children = boxes(out, meta.body + 4, meta.end);
            const auto iinf = std::ranges::find(children, "iinf"sv, &Box::type);
            const auto iloc = std::ranges::find(children, "iloc"sv, &Box::type);
            const auto idat = std::ranges::find(children, "idat"sv, &Box::type);
            if (iinf == children.end() || iloc == children.end())
                continue;
            const auto locations =
                    item_locations(out, *iloc, idat == children.end() ? nullptr : &*idat);

            for (const auto& item : metadata_items(out, *iinf)) {
                const auto found = locations.find(item.id);
                if (found == locations.end())
                    continue;
                if (!found->second.located)
                    throw std::runtime_error{
                            "a HEIF metadata item is stored where it cannot be read"};
                const auto& extents = found->second.spans;
                if (item.exif && extents.size() == 1) {
                    // A 4-byte offset to the TIFF header, then whatever precedes it.
                    auto [at, length] = extents[0];
                    auto data = mutable_bytes{out}.subspan(at, length);
                    if (data.size() >= 4 && be32(data, 0) <= data.size() - 4) {
                        auto r = empty_gps(data.subspan(4 + be32(data, 0)));
                        if (r == Exif::emptied)
                            changed = true;
                        if (r != Exif::unreadable)
                            continue;
                    }
                }
                // Blanked where it lies: EXIF in several pieces or unreadable is zeroed whole, and
                // XMP naming a place becomes spaces, which XMP allows as padding.
                std::string text;
                for (auto [at, length] : extents)
                    text += text_of(bytes{out}.subspan(at, length));
                if (!item.exif && !names_a_place(text))
                    continue;
                if (item.exif && std::ranges::all_of(text, [](char c) { return c == '\0'; }))
                    continue;
                for (auto [at, length] : extents)
                    fill(out, at, at + length, item.exif ? std::byte{0} : std::byte{' '});
                changed |= !extents.empty();
            }
        }
        if (!changed)
            return std::nullopt;
        return out;
    }

    bool is_jpeg(bytes b) {
        return fits(b, 0, 3) && u8(b, 0) == 0xFF && u8(b, 1) == SOI && u8(b, 2) == 0xFF;
    }
    bool is_png(bytes b) {
        return has_at(b, 0, PNG_SIGNATURE);
    }
    bool is_webp(bytes b) {
        return has_at(b, 0, "RIFF") && has_at(b, 8, "WEBP");
    }
    bool is_heif(bytes b) {
        constexpr std::array brands{
                "heic"sv,
                "heix"sv,
                "heim"sv,
                "heis"sv,
                "hevc"sv,
                "hevx"sv,
                "mif1"sv,
                "msf1"sv,
                "avif"sv,
                "avis"sv};
        if (!has_at(b, 4, "ftyp"))
            return false;
        // The major brand, then the compatible ones, as far as `b` holds them.
        const uint64_t end = std::min<uint64_t>(be32(b, 0), b.size());
        for (uint64_t at = 8; at + 4 <= end; at += at == 8 ? 8 : 4)
            if (std::ranges::any_of(brands, [&](std::string_view s) { return has_at(b, at, s); }))
                return true;
        return false;
    }

}  // namespace

bool may_carry_location(std::span<const std::byte> head) {
    return head.size() >= 12 && (is_jpeg(head) || is_png(head) || is_webp(head) || is_heif(head));
}

std::optional<std::vector<std::byte>> without_location(std::span<const std::byte> file) {
    if (!may_carry_location(file))
        return std::nullopt;
    if (is_jpeg(file))
        return jpeg_without_location(file);
    if (is_png(file))
        return png_without_location(file);
    if (is_webp(file))
        return webp_without_location(file);
    return heif_without_location(file);
}

}  // namespace session::image
