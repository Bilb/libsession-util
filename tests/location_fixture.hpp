#pragma once

// Pictures carrying location metadata, built byte by byte, for the location tests.

#include <vips/vips.h>

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>
#include <session/image/vips.hpp>
#include <string_view>
#include <vector>

#include "../src/image/vips_internal.hpp"

namespace location_fixture {

namespace image = session::image;
using image::detail::image_ptr;
using namespace std::literals;

using buffer = std::vector<std::byte>;

// What every GPS value in these tests is made of, so its absence is easy to check.
constexpr std::byte MARK{0xA7};

inline buffer bytes_of(std::string_view s) {
    buffer out(s.size());
    std::memcpy(out.data(), s.data(), s.size());
    return out;
}

inline bool contains(const buffer& hay, std::string_view needle) {
    std::string_view h{reinterpret_cast<const char*>(hay.data()), hay.size()};
    return h.find(needle) != h.npos;
}

inline size_t occurrences(const buffer& hay, std::string_view needle) {
    std::string_view h{reinterpret_cast<const char*>(hay.data()), hay.size()};
    size_t n = 0;
    for (auto at = h.find(needle); at != h.npos; at = h.find(needle, at + 1))
        n++;
    return n;
}

inline size_t count_marks(const buffer& b) {
    return static_cast<size_t>(std::ranges::count(b, MARK));
}

struct Writer {
    bool le;
    buffer out;
    void u8(uint8_t v) { out.push_back(std::byte{v}); }
    void u16(uint32_t v) {
        if (le) {
            u8(v & 0xFF);
            u8(v >> 8);
        } else {
            u8(v >> 8);
            u8(v & 0xFF);
        }
    }
    void u32(uint32_t v) {
        if (le) {
            u16(v & 0xFFFF);
            u16(v >> 16);
        } else {
            u16(v >> 16);
            u16(v & 0xFFFF);
        }
    }
    void entry(uint32_t tag, uint32_t type, uint32_t count, uint32_t value) {
        u16(tag);
        u16(type);
        u32(count);
        if (type == 3 && count == 1) {
            u16(value);
            u16(0);
        } else
            u32(value);
    }
};

// A TIFF structure as EXIF holds it: orientation 6, and a GPS directory with a latitude reference
// and a latitude (three rationals, so held outside the entry), all of them MARK bytes.
inline buffer exif_tiff(bool le, bool with_gps = true) {
    Writer w{le};
    w.u8(le ? 'I' : 'M');
    w.u8(le ? 'I' : 'M');
    w.u16(42);
    w.u32(8);
    const uint32_t ifd0_entries = with_gps ? 2 : 1;
    w.u16(ifd0_entries);
    w.entry(0x0112, 3, 1, 6);
    const uint32_t gps_at = 8 + 2 + 12 * ifd0_entries + 4;
    if (with_gps)
        w.entry(0x8825, 4, 1, gps_at);
    w.u32(0);
    if (!with_gps)
        return w.out;

    const uint32_t values_at = gps_at + 2 + 12 * 2 + 4;
    w.u16(2);
    w.entry(0x0001, 2, 2, 0);  // the reference, inline: rewritten as MARKs below
    w.out.resize(w.out.size() - 4);
    for (int i = 0; i < 4; i++)
        w.out.push_back(MARK);
    w.entry(0x0002, 5, 3, values_at);
    w.u32(0);
    for (int i = 0; i < 24; i++)
        w.out.push_back(MARK);
    return w.out;
}

inline image_ptr test_picture(int w = 32, int h = 24) {
    image::init();
    VipsImage* black;
    REQUIRE(vips_black(&black, w, h, "bands", 3, nullptr) == 0);
    VipsImage* img;
    REQUIRE(vips_cast_uchar(black, &img, nullptr) == 0);
    g_object_unref(black);
    return image_ptr{img};
}

inline buffer saved(const char* format) {
    auto img = test_picture();
    void* buf = nullptr;
    size_t len = 0;
    int rc = format == "jpeg"sv ? vips_jpegsave_buffer(img.get(), &buf, &len, nullptr)
           : format == "png"sv  ? vips_pngsave_buffer(img.get(), &buf, &len, nullptr)
                                : vips_webpsave_buffer(img.get(), &buf, &len, nullptr);
    REQUIRE(rc == 0);
    buffer out(len);
    std::memcpy(out.data(), buf, len);
    g_free(buf);
    return out;
}

// Decodes `file` whole; the orientation it reports, or -1 if it would not load.
inline int decoded_orientation(const buffer& file) {
    image::init();
    image_ptr img{vips_image_new_from_buffer(file.data(), file.size(), "", nullptr)};
    if (!img)
        return -1;
    double avg;
    if (vips_avg(img.get(), &avg, nullptr) != 0)
        return -1;
    int orientation = 1;
    if (vips_image_get_typeof(img.get(), "orientation"))
        vips_image_get_int(img.get(), "orientation", &orientation);
    return orientation;
}

// MARK: JPEG

inline buffer jpeg_segment(uint8_t marker, const buffer& payload) {
    buffer s{std::byte{0xFF}, std::byte{marker}};
    const size_t len = payload.size() + 2;
    s.push_back(std::byte(len >> 8));
    s.push_back(std::byte(len & 0xFF));
    s.insert(s.end(), payload.begin(), payload.end());
    return s;
}

inline buffer exif_segment(const buffer& tiff) {
    auto payload = bytes_of("Exif\0\0"sv);
    payload.insert(payload.end(), tiff.begin(), tiff.end());
    return jpeg_segment(0xE1, payload);
}

inline buffer xmp_segment(std::string_view packet) {
    auto payload = bytes_of("http://ns.adobe.com/xap/1.0/\0"sv);
    auto p = bytes_of(packet);
    payload.insert(payload.end(), p.begin(), p.end());
    return jpeg_segment(0xE1, payload);
}

inline buffer extended_xmp_segment(std::string_view chunk) {
    auto payload = bytes_of("http://ns.adobe.com/xmp/extension/\0"sv);
    payload.resize(payload.size() + 40, std::byte{'0'});
    auto p = bytes_of(chunk);
    payload.insert(payload.end(), p.begin(), p.end());
    return jpeg_segment(0xE1, payload);
}

// A decodable JPEG with `segments` right after its SOI.
inline buffer jpeg_with(std::vector<buffer> segments) {
    auto plain = saved("jpeg");
    buffer out{plain.begin(), plain.begin() + 2};
    for (auto& s : segments)
        out.insert(out.end(), s.begin(), s.end());
    out.insert(out.end(), plain.begin() + 2, plain.end());
    return out;
}

// MARK: HEIF

inline buffer heif_box(std::string_view type, const buffer& body) {
    Writer w{false};
    w.u32(static_cast<uint32_t>(body.size() + 8));
    for (char c : type)
        w.u8(c);
    w.out.insert(w.out.end(), body.begin(), body.end());
    return w.out;
}

inline buffer full_box(std::string_view type, uint8_t version, const buffer& body) {
    buffer b{std::byte{version}, {}, {}, {}};
    b.insert(b.end(), body.begin(), body.end());
    return heif_box(type, b);
}

// A HEIC holding one metadata item, `item`, of type `type` ("Exif", or "mime" for XMP).
struct HeifLayout {
    uint8_t iloc_version = 0;
    uint16_t method = 0;  // 1 puts the item in `idat`
    std::string_view major = "heic";
};

inline buffer heif_with(std::string_view type, const buffer& item, HeifLayout layout = {}) {
    auto build = [&](uint32_t offset) {
        Writer infe{false};
        infe.u16(1);
        infe.u16(0);
        for (char c : type)
            infe.u8(c);
        infe.u8(0);  // name
        if (type == "mime")
            for (char c : "application/rdf+xml"sv)
                infe.u8(c);
        if (type == "mime")
            infe.u8(0);
        Writer iinf{false};
        iinf.u16(1);
        auto entry = full_box("infe", 2, infe.out);
        iinf.out.insert(iinf.out.end(), entry.begin(), entry.end());

        Writer iloc{false};
        iloc.u8(0x44);
        iloc.u8(0x00);
        iloc.u16(1);
        iloc.u16(1);  // item id
        if (layout.iloc_version > 0)
            iloc.u16(layout.method);
        iloc.u16(0);  // data reference
        iloc.u16(1);  // extents
        iloc.u32(layout.method == 1 ? 0 : offset);
        iloc.u32(static_cast<uint32_t>(item.size()));

        buffer meta_body;
        for (auto b :
             {full_box("iinf", 0, iinf.out), full_box("iloc", layout.iloc_version, iloc.out)})
            meta_body.insert(meta_body.end(), b.begin(), b.end());
        if (layout.method == 1) {
            auto idat = heif_box("idat", item);
            meta_body.insert(meta_body.end(), idat.begin(), idat.end());
        }
        auto ftyp = bytes_of(layout.major);
        auto brands = bytes_of("\0\0\0\0mif1heic"sv);
        ftyp.insert(ftyp.end(), brands.begin(), brands.end());
        auto file = heif_box("ftyp", ftyp);
        auto meta = full_box("meta", 0, meta_body);
        file.insert(file.end(), meta.begin(), meta.end());
        auto mdat = heif_box("mdat", layout.method == 1 ? buffer{} : item);
        file.insert(file.end(), mdat.begin(), mdat.end());
        return file;
    };
    auto probe = build(0);
    return build(static_cast<uint32_t>(probe.size() - (layout.method == 1 ? 0 : item.size())));
}

inline buffer exif_item(bool with_gps = true) {
    Writer item{false};
    item.u32(6);
    auto exif = bytes_of("Exif\0\0"sv);
    auto tiff = exif_tiff(false, with_gps);
    item.out.insert(item.out.end(), exif.begin(), exif.end());
    item.out.insert(item.out.end(), tiff.begin(), tiff.end());
    return item.out;
}

}  // namespace location_fixture
