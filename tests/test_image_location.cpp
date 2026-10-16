#include <catch2/catch_test_macros.hpp>
#include <session/image/location.hpp>

#include "location_fixture.hpp"

using namespace location_fixture;

namespace {

constexpr auto PLACE_XMP =
        R"(<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description exif:GPSLatitude="51,30.0N" photoshop:City="London"/></rdf:RDF></x:xmpmeta>)"sv;
constexpr auto HDR_XMP =
        R"(<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description hdrgm:Version="1.0"/></rdf:RDF></x:xmpmeta>)"sv;

}  // namespace

TEST_CASE("Location: a JPEG's GPS directory is emptied and the rest kept", "[image][location]") {
    for (bool le : {true, false}) {
        INFO("little-endian " << le);
        auto file = jpeg_with({exif_segment(exif_tiff(le))});
        REQUIRE(count_marks(file) >= 28);

        auto out = image::without_location(file);
        REQUIRE(out);
        CHECK(out->size() == file.size());
        CHECK(count_marks(*out) == count_marks(file) - 28);
        CHECK(decoded_orientation(*out) == 6);
        CHECK_FALSE(image::without_location(*out));
    }
}

TEST_CASE("Location: a JPEG with nothing to remove is not copied", "[image][location]") {
    CHECK_FALSE(image::without_location(saved("jpeg")));
    CHECK_FALSE(image::without_location(jpeg_with({exif_segment(exif_tiff(true, false))})));
    CHECK_FALSE(image::without_location(jpeg_with({xmp_segment(HDR_XMP)})));
}

TEST_CASE("Location: EXIF that cannot be walked is removed whole", "[image][location]") {
    auto tiff = exif_tiff(true);
    tiff[4] = std::byte{0xF0};  // IFD0 offset past the end
    auto file = jpeg_with({exif_segment(tiff)});

    auto out = image::without_location(file);
    REQUIRE(out);
    CHECK(out->size() == file.size());
    // libvips writes EXIF of its own into the picture, after ours.
    CHECK(occurrences(*out, "Exif\0\0"sv) == occurrences(file, "Exif\0\0"sv) - 1);
    CHECK(count_marks(*out) == count_marks(file) - 28);
    CHECK(decoded_orientation(*out) == 1);
}

TEST_CASE("Location: XMP naming a place goes, other XMP stays", "[image][location]") {
    auto file = jpeg_with({xmp_segment(PLACE_XMP), xmp_segment(HDR_XMP)});
    auto out = image::without_location(file);
    REQUIRE(out);
    CHECK(out->size() == file.size());
    CHECK_FALSE(contains(*out, "GPSLatitude"));
    CHECK_FALSE(contains(*out, "London"));
    // Both packets are one picture's XMP, so both go.
    CHECK_FALSE(contains(*out, "hdrgm"));
    CHECK(decoded_orientation(*out) == 1);
}

TEST_CASE("Location: a GPS field split across extended XMP is found", "[image][location]") {
    auto file = jpeg_with(
            {xmp_segment(HDR_XMP),
             extended_xmp_segment("<rdf:Description exif:GP"),
             extended_xmp_segment("SLongitude=\"0,7.5W\"/>")});
    auto out = image::without_location(file);
    REQUIRE(out);
    CHECK_FALSE(contains(*out, "Longitude"));
    CHECK_FALSE(contains(*out, "hdrgm"));
}

TEST_CASE("Location: Photoshop resource blocks go", "[image][location]") {
    auto payload = bytes_of("Photoshop 3.0\0008BIM\x04\x04"sv);
    payload.push_back(MARK);
    auto file = jpeg_with({jpeg_segment(0xED, payload)});
    auto out = image::without_location(file);
    REQUIRE(out);
    CHECK_FALSE(contains(*out, "Photoshop"));
    CHECK(count_marks(*out) == count_marks(file) - 1);
}

TEST_CASE("Location: each picture of a multi-picture JPEG is read", "[image][location]") {
    // The second picture carries the GPS; the first's MPF index points at it.
    auto second = jpeg_with({exif_segment(exif_tiff(true))});

    auto mpf = [](uint32_t offset, uint32_t size) {
        Writer w{true};
        for (char c : "MPF\0II"sv)
            w.u8(c);
        w.u16(42);
        w.u32(8);
        w.u16(1);
        w.entry(0xB002, 7, 32, 8 + 2 + 12 + 4);
        w.u32(0);
        w.u32(0x030000);  // primary
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);  // the second
        w.u32(size);
        w.u32(offset);
        w.u32(0);
        return jpeg_segment(0xE2, w.out);
    };
    auto first = jpeg_with({mpf(0, 0)});
    // Where the index begins: SOI, the marker and length, then "MPF\0".
    const uint32_t index_at = 2 + 4 + 4;
    auto with_offset =
            jpeg_with({mpf(static_cast<uint32_t>(first.size() - index_at), second.size())});
    REQUIRE(with_offset.size() == first.size());
    buffer file = with_offset;
    file.insert(file.end(), second.begin(), second.end());

    auto out = image::without_location(file);
    REQUIRE(out);
    CHECK(out->size() == file.size());
    CHECK(count_marks(*out) == count_marks(file) - 28);

    // Without the index, bytes after the first picture are left alone.
    buffer unindexed = saved("jpeg");
    unindexed.insert(unindexed.end(), second.begin(), second.end());
    CHECK_FALSE(image::without_location(unindexed));
}

// MARK: PNG

namespace {

uint32_t crc32(const std::byte* p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= static_cast<uint8_t>(p[i]);
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
    }
    return c ^ 0xFFFFFFFFu;
}

buffer png_chunk(std::string_view type, const buffer& data) {
    Writer w{false};
    w.u32(static_cast<uint32_t>(data.size()));
    for (char c : type)
        w.u8(c);
    w.out.insert(w.out.end(), data.begin(), data.end());
    w.u32(crc32(w.out.data() + 4, w.out.size() - 4));
    return w.out;
}

// A decodable PNG with `chunks` right after its IHDR.
buffer png_with(std::vector<buffer> chunks) {
    auto plain = saved("png");
    constexpr size_t after_ihdr = 8 + 25;
    buffer out{plain.begin(), plain.begin() + after_ihdr};
    for (auto& c : chunks)
        out.insert(out.end(), c.begin(), c.end());
    out.insert(out.end(), plain.begin() + after_ihdr, plain.end());
    return out;
}

// Every chunk's CRC matches its contents.
bool png_crcs_hold(const buffer& png) {
    for (size_t i = 8; i + 12 <= png.size();) {
        auto u32 = [&](size_t at) {
            return (uint32_t(png[at]) << 24) | (uint32_t(png[at + 1]) << 16) |
                   (uint32_t(png[at + 2]) << 8) | uint32_t(png[at + 3]);
        };
        const size_t len = u32(i);
        if (u32(i + 8 + len) != crc32(png.data() + i + 4, len + 4))
            return false;
        i += 12 + len;
    }
    return true;
}

buffer itxt(std::string_view keyword, bool compressed, std::string_view text) {
    auto data = bytes_of(keyword);
    data.push_back(std::byte{0});
    data.push_back(std::byte{compressed});
    data.push_back(std::byte{0});
    data.push_back(std::byte{0});  // language
    data.push_back(std::byte{0});  // translated keyword
    auto t = bytes_of(text);
    data.insert(data.end(), t.begin(), t.end());
    return png_chunk("iTXt", data);
}

}  // namespace

TEST_CASE("Location: a PNG's eXIf GPS is emptied with its CRC redone", "[image][location]") {
    auto file = png_with({png_chunk("eXIf", exif_tiff(false))});
    auto out = image::without_location(file);
    REQUIRE(out);
    CHECK(out->size() == file.size());
    CHECK(count_marks(*out) == count_marks(file) - 28);
    CHECK(png_crcs_hold(*out));
    CHECK(decoded_orientation(*out) == 6);
}

TEST_CASE("Location: PNG text that can hold a place goes", "[image][location]") {
    auto keep = png_chunk("tEXt", bytes_of("Comment\0a holiday"sv));
    auto file = png_with(
            {keep,
             itxt("XML:com.adobe.xmp", false, PLACE_XMP),
             itxt("XML:com.adobe.xmp", true, "compressed, so unread"),
             png_chunk("tEXt", bytes_of("Raw profile type exif\0\n exif\n 4\n41424344"sv)),
             png_chunk("zTXt", bytes_of("Raw profile type iptc\0\0compressed"sv))});
    auto out = image::without_location(file);
    REQUIRE(out);
    CHECK(contains(*out, "a holiday"));
    CHECK_FALSE(contains(*out, "XML:com.adobe.xmp"));
    CHECK_FALSE(contains(*out, "Raw profile"));
    CHECK(png_crcs_hold(*out));
    CHECK(decoded_orientation(*out) == 1);

    CHECK_FALSE(
            image::without_location(png_with({keep, itxt("XML:com.adobe.xmp", false, HDR_XMP)})));
}

// MARK: WebP

namespace {

buffer webp_chunk(std::string_view fourcc, const buffer& data) {
    Writer w{true};
    for (char c : fourcc)
        w.u8(c);
    w.u32(static_cast<uint32_t>(data.size()));
    w.out.insert(w.out.end(), data.begin(), data.end());
    if (data.size() & 1)
        w.u8(0);
    return w.out;
}

// The extended form, with the flags `chunks` call for, around a plain WebP's image chunk.
buffer webp_with(uint8_t flags, std::vector<buffer> chunks) {
    auto plain = saved("webp");
    // The image chunk, after the VP8X that libvips may already have written.
    size_t image_at = 12;
    if (std::string_view{reinterpret_cast<const char*>(plain.data()) + 12, 4} == "VP8X")
        image_at += 8 + 10;
    REQUIRE(std::string_view{reinterpret_cast<const char*>(plain.data()) + image_at, 4} == "VP8 ");
    buffer vp8x{std::byte{flags}, {}, {}, {}};
    for (uint32_t v : {32u - 1, 24u - 1})
        for (int i = 0; i < 3; i++)
            vp8x.push_back(std::byte((v >> (8 * i)) & 0xFF));

    buffer body = bytes_of("WEBP");
    auto x = webp_chunk("VP8X", vp8x);
    body.insert(body.end(), x.begin(), x.end());
    body.insert(body.end(), plain.begin() + image_at, plain.end());
    for (auto& c : chunks)
        body.insert(body.end(), c.begin(), c.end());

    Writer w{true};
    for (char c : "RIFF"sv)
        w.u8(c);
    w.u32(static_cast<uint32_t>(body.size()));
    w.out.insert(w.out.end(), body.begin(), body.end());
    return w.out;
}

uint32_t riff_size(const buffer& b) {
    return uint32_t(b[4]) | (uint32_t(b[5]) << 8) | (uint32_t(b[6]) << 16) | (uint32_t(b[7]) << 24);
}

}  // namespace

TEST_CASE("Location: a WebP's EXIF GPS is emptied in place", "[image][location]") {
    auto file = webp_with(0x08, {webp_chunk("EXIF", exif_tiff(true))});
    REQUIRE(decoded_orientation(file) != -1);
    auto out = image::without_location(file);
    REQUIRE(out);
    CHECK(out->size() == file.size());
    CHECK(count_marks(*out) == count_marks(file) - 28);
    CHECK(decoded_orientation(*out) != -1);
}

TEST_CASE("Location: a WebP's XMP naming a place goes, with its flag", "[image][location]") {
    auto file = webp_with(0x04, {webp_chunk("XMP ", bytes_of(PLACE_XMP))});
    auto out = image::without_location(file);
    REQUIRE(out);
    CHECK_FALSE(contains(*out, "XMP "));
    CHECK(riff_size(*out) == out->size() - 8);
    CHECK((static_cast<uint8_t>((*out)[20]) & 0x04) == 0);
    CHECK(decoded_orientation(*out) != -1);

    CHECK_FALSE(image::without_location(webp_with(0x04, {webp_chunk("XMP ", bytes_of(HDR_XMP))})));
}

// MARK: Everything else

TEST_CASE("Location: only JPEG, PNG and WebP are read", "[image][location]") {
    CHECK_FALSE(image::may_carry_location(bytes_of("GIF89a\x01\0\x01\0\0\0"sv)));
    CHECK_FALSE(image::may_carry_location(bytes_of("\xFF\xD8\xFF"sv)));
    CHECK(image::may_carry_location(saved("jpeg")));
    CHECK(image::may_carry_location(saved("png")));
    CHECK(image::may_carry_location(saved("webp")));
    CHECK_FALSE(image::without_location(bytes_of("%PDF-1.7 GPS City Location"sv)));
}

TEST_CASE("Location: a truncated or damaged file never reads out of bounds", "[image][location]") {
    // Meant for the sanitizers: every prefix, and every byte flipped, of one file of each kind.
    for (auto file :
         {jpeg_with({exif_segment(exif_tiff(true)), xmp_segment(PLACE_XMP)}),
          png_with(
                  {png_chunk("eXIf", exif_tiff(false)),
                   itxt("XML:com.adobe.xmp", false, PLACE_XMP)}),
          webp_with(
                  0x0C,
                  {webp_chunk("EXIF", exif_tiff(true)),
                   webp_chunk("XMP ", bytes_of(PLACE_XMP))})}) {
        for (size_t n = 0; n <= file.size(); n++) {
            buffer prefix{file.begin(), file.begin() + n};
            (void)image::without_location(prefix);
        }
        for (size_t i = 0; i < std::min<size_t>(file.size(), 400); i++) {
            buffer damaged = file;
            damaged[i] ^= std::byte{0xFF};
            (void)image::without_location(damaged);
        }
    }
}
