#include <libheif/heif.h>

#include <catch2/catch_test_macros.hpp>
#include <cstdio>
#include <optional>
#include <session/attachments.hpp>
#include <session/image/sendable.hpp>
#include <session/image/thumbnail.hpp>
#include <set>
#include <string_view>
#include <utility>

#include "image_drawing.hpp"
#include "image_fixtures.hpp"

using namespace image_test;
using namespace std::literals;

namespace {

using bytes = std::vector<std::byte>;

// `jpeg` with its progressive frame header claiming `sampling` for every component, and the size
// given if any: a header libvips reads as subsampled whatever the factors' real effect.
bytes patched_sof(bytes jpeg, uint8_t sampling, std::optional<std::pair<uint16_t, uint16_t>> size) {
    auto text = std::string_view{reinterpret_cast<const char*>(jpeg.data()), jpeg.size()};
    auto sof = text.find("\xFF\xC2"sv);
    REQUIRE(sof != std::string_view::npos);
    if (size) {
        auto [w, h] = *size;
        jpeg[sof + 5] = std::byte(h >> 8);
        jpeg[sof + 6] = std::byte(h & 0xFF);
        jpeg[sof + 7] = std::byte(w >> 8);
        jpeg[sof + 8] = std::byte(w & 0xFF);
    }
    auto n = static_cast<size_t>(jpeg[sof + 9]);
    for (size_t i = 0; i < n; i++)
        jpeg[sof + 10 + 3 * i + 1] = std::byte{sampling};
    return jpeg;
}

std::string_view text(const bytes& b) {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

uint32_t u16be(const bytes& b, size_t at) {
    return (uint32_t(b[at]) << 8) | uint32_t(b[at + 1]);
}
uint32_t u32le(const bytes& b, size_t at) {
    return uint32_t(b[at]) | (uint32_t(b[at + 1]) << 8) | (uint32_t(b[at + 2]) << 16) |
           (uint32_t(b[at + 3]) << 24);
}

// What a re-encoded file is made of, by JPEG marker or RIFF chunk: the whole of the guarantee is
// that nothing outside these lists can be in it.
std::set<std::string> parts(const bytes& b) {
    std::set<std::string> out;
    if (text(b).starts_with("RIFF")) {
        for (size_t at = 12; at + 8 <= b.size();
             at += 8 + u32le(b, at + 4) + (u32le(b, at + 4) & 1))
            out.insert(std::string{text(b).substr(at, 4)});
        return out;
    }
    for (size_t at = 2; at + 4 <= b.size() && b[at] == std::byte{0xFF};) {
        auto marker = uint8_t(b[at + 1]);
        char hex[3];
        std::snprintf(hex, sizeof hex, "%02X", marker);
        out.insert(hex);
        if (marker == 0xDA)
            break;
        at += 2 + u16be(b, at + 2);
    }
    return out;
}

const std::set<std::string> JPEG_PARTS{"E0", "DB", "C0", "C2", "C4", "DD", "DA"};
const std::set<std::string> WEBP_PARTS{"VP8 ", "VP8L", "VP8X", "ALPH", "ANIM", "ANMF"};

// Everything a camera or an editor attaches, so that the test sees none of it come through.
image_ptr tagged(image_ptr img) {
    vips_image_set_int(img.get(), "orientation", 6);
    vips_image_set_string(img.get(), "exif-ifd0-Artist", "SecretArtist");
    constexpr auto xmp =
            "<x:xmpmeta><rdf:Description photoshop:City=\"SecretCity\"/></x:xmpmeta>"sv;
    vips_image_set_blob_copy(img.get(), "xmp-data", xmp.data(), xmp.size());
    return img;
}

rgba gradient(int x, int y) {
    return {uint8_t(x), uint8_t(y), uint8_t(x ^ y), 255};
}
rgba fading(int x, int y) {
    return {uint8_t(x * 4), 80, uint8_t(y * 4), uint8_t(x * 255 / 64)};
}

image_ptr animation(int w, int h, int bands) {
    auto img = draw(
            w,
            h,
            [](int x, int y) { return rgba{uint8_t(y * 6), uint8_t(x * 6), 50, 255}; },
            bands,
            3);
    std::vector<int> delays{100, 200, 300};
    vips_image_set_array_int(img.get(), "delay", delays.data(), int(delays.size()));
    return img;
}

struct Case {
    const char* what;
    bytes file;
    // Empty when the file cannot be re-encoded.
    std::string_view type;
    uint32_t width = 0, height = 0, frames = 1;
    bool alpha = false;
};

std::vector<Case> cases() {
    std::vector<Case> out{
            {"a sideways JPEG with metadata",
             save(tagged(draw(300, 200, gradient)).get(), ".jpg"),
             "image/jpeg",
             200,
             300},
            {"a wide JPEG",
             save(draw(3000, 1000, gradient).get(), ".jpg"),
             "image/jpeg",
             2048,
             683},
            {"a tall opaque PNG",
             save(draw(1000, 3000, gradient).get(), ".png"),
             "image/jpeg",
             683,
             2048},
            {"a PNG with transparency",
             save(draw(64, 48, fading, 4).get(), ".png"),
             "image/webp",
             64,
             48,
             1,
             true},
            {"an opaque WebP", save(draw(64, 48, gradient).get(), ".webp"), "image/jpeg", 64, 48},
            {"a WebP with transparency",
             save(draw(64, 48, fading, 4).get(), ".webp"),
             "image/webp",
             64,
             48,
             1,
             true},
            {"an animated GIF", save(animation(40, 30, 3).get(), ".gif"), "image/webp", 40, 30, 3},
            {"an animated WebP",
             save(animation(40, 30, 4).get(), ".webp"),
             "image/webp",
             40,
             30,
             3,
             true},
            {"a wide animated GIF",
             save(animation(2100, 40, 3).get(), ".gif"),
             "image/webp",
             2048,
             39,
             3},
            {"a PDF", bytes(400, std::byte{'%'}), ""},
    };
    // HEIC decodes through ImageIO on Apple, and elsewhere only with a HEVC decoder in libheif.
    std::span<const std::byte> heic{image_fixtures::heic_64x48};
    bool decodes = heif_have_decoder_for_format(heif_compression_HEVC);
#ifdef __APPLE__
    decodes = true;
#endif
    out.push_back({"a HEIC", bytes{heic.begin(), heic.end()}, decodes ? "image/jpeg" : "", 64, 48});
    return out;
}

}  // namespace

TEST_CASE(
        "Sendable: every picture is re-encoded as jpegli or WebP, and nothing else survives",
        "[image][sendable]") {
    for (auto& c : cases()) {
        INFO(c.what);
        image::Source source{std::span<const std::byte>{c.file}};
        if (c.type.empty()) {
            CHECK_THROWS_AS(image::sendable(source, 10'000'000), std::runtime_error);
            continue;
        }
        auto out = image::sendable(source, 10'000'000);
        REQUIRE(out);
        CHECK(out->content_type == c.type);
        CHECK(out->width == c.width);
        CHECK(out->height == c.height);
        CHECK(out->frames == c.frames);

        auto found = parts(out->bytes);
        const auto& allowed = c.type == "image/jpeg" ? JPEG_PARTS : WEBP_PARTS;
        for (const auto& p : found) {
            INFO("part " << p);
            CHECK(allowed.contains(p));
        }
        CHECK(found.contains("ALPH") == (c.alpha && c.frames == 1));
        if (c.frames > 1) {
            image_ptr sent{vips_image_new_from_buffer(
                    out->bytes.data(), out->bytes.size(), "n=-1", nullptr)};
            REQUIRE(sent);
            int* delays = nullptr;
            int n = 0;
            REQUIRE(vips_image_get_array_int(sent.get(), "delay", &delays, &n) == 0);
            CHECK(std::vector<int>(delays, delays + n) == std::vector<int>{100, 200, 300});
        }
        for (auto secret : {"SecretArtist"sv, "SecretCity"sv, "Exif"sv})
            CHECK(text(out->bytes).find(secret) == std::string_view::npos);

        image::Source again{std::span<const std::byte>{c.file}};
        CHECK(image::sendable(again, 10'000'000)->bytes == out->bytes);
    }
}

TEST_CASE(
        "Sendable: an animated PNG is not re-encoded, which would send a still",
        "[image][sendable]") {
    auto apng = animated_png(save(draw(40, 30, [](int, int) { return RED; }).get(), ".png"));
    image::Source source{std::span<const std::byte>{apng}};
    auto info = image::probe(source);
    REQUIRE(info);
    CHECK(image::sendable_verdict(*info) == image::SendableVerdict::cannot_decode);
    CHECK_THROWS_AS(image::sendable(source, 10'000'000), std::runtime_error);
}

TEST_CASE(
        "Sendable: a 45 MP progressive photo is re-encoded and has a thumbnail",
        "[image][sendable][thumbnail]") {
    // What a camera writes: 8134x5562, chroma subsampled.  Solid, so that it encodes quickly.
    image::init();
    VipsImage *black, *srgb;
    REQUIRE(vips_black(&black, 8134, 5562, "bands", 3, nullptr) == 0);
    image_ptr b{black};
    REQUIRE(vips_copy(black, &srgb, "interpretation", VIPS_INTERPRETATION_sRGB, nullptr) == 0);
    image_ptr photo{srgb};

    auto check = [&](const char* suffix, bool sends) {
        INFO(suffix);
        auto jpeg = save(photo.get(), suffix);
        image::Source source{std::span<const std::byte>{jpeg}};
        auto info = image::probe(source);
        REQUIRE(info);
        CHECK(info->decoded_whole);
        CHECK(image::thumbnail(source, 256));
        CHECK(image::sendable_verdict(*info) ==
              (sends ? image::SendableVerdict::encode : image::SendableVerdict::too_large));
        if (!sends)
            return;
        auto out = image::sendable(source, 10'000'000);
        REQUIRE(out);
        CHECK(out->width == 2048);
        CHECK(out->height == 1400);
    };
    check(".jpg[interlace,subsample_mode=on]", true);
    // Unsubsampled, its coefficients and full-size decode for a 2048 box are over the budget.
    check(".jpg[interlace,subsample_mode=off]", false);

    // Every component at 2x1 is subsampled to libvips, but each is still at full resolution.
    auto all_wide = patched_sof(save(photo.get(), ".jpg[interlace,subsample_mode=off]"), 0x21, {});
    image::Source source{std::span<const std::byte>{all_wide}};
    auto info = image::probe(source);
    REQUIRE(info);
    CHECK(image::sendable_verdict(*info) == image::SendableVerdict::too_large);
}

TEST_CASE(
        "Sendable: a tiny progressive JPEG claiming a huge frame of full-size components gets no "
        "thumbnail",
        "[image][sendable][thumbnail]") {
    // A couple of KB that would have libjpeg allocate about 500 MB of coefficients.
    auto small = save(
            draw(64, 48, [](int, int) { return RED; }).get(), ".jpg[interlace,subsample_mode=off]");
    auto bomb = patched_sof(small, 0x21, std::pair<uint16_t, uint16_t>{11000, 7600});
    image::Source source{std::span<const std::byte>{bomb}};
    auto info = image::probe(source);
    REQUIRE(info);
    CHECK(info->width == 11000);
    CHECK(info->coefficient_bytes == 3ull * 1376 * 950 * 128);
    CHECK_FALSE(image::thumbnail(source, 256));
}

TEST_CASE(
        "Sendable: a picture too large for the limit is shrunk until it fits",
        "[image][sendable]") {
    auto noise =
            save(draw(2048,
                      2048,
                      [](int x, int y) {
                          uint32_t v = uint32_t(x) * 2654435761u ^ uint32_t(y) * 40503u;
                          return rgba{uint8_t(v), uint8_t(v >> 8), uint8_t(v >> 16), 255};
                      }).get(),
                 ".png");
    image::Source source{std::span<const std::byte>{noise}};
    auto out = image::sendable(source, 400'000);
    REQUIRE(out);
    CHECK(session::attachment::encrypted_size(out->bytes.size()) <= 400'000);
    CHECK(out->width < 2048);
    CHECK(out->width >= image::min_sendable_edge);

    image::Source again{std::span<const std::byte>{noise}};
    CHECK_FALSE(image::sendable(again, 2'000));
}
