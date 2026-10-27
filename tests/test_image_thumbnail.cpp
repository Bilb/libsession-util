#include <libheif/heif.h>
#include <oxenc/hex.h>
#include <vips/vips.h>

#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <session/attachments.hpp>
#include <session/image/probe.hpp>
#include <session/image/thumbhash.hpp>
#include <session/image/thumbnail.hpp>
#include <session/image/vips.hpp>
#include <session/random.hpp>
#include <string>
#include <vector>

#include "../src/image/thumbnail_internal.hpp"
#include "../src/image/vips_internal.hpp"
#include "image_drawing.hpp"
#include "image_fixtures.hpp"

namespace image = session::image;
using image::detail::image_ptr;
using image_test::rgba;

namespace {

using namespace image_test;

std::optional<std::vector<std::byte>> thumb(std::span<const std::byte> data, uint32_t edge) {
    image::Source src{data};
    return image::thumbnail(src, edge);
}

}  // namespace

TEST_CASE("thumbnail makes a JPEG with no metadata", "[image][thumbnail]") {
    auto photo = draw(640, 480, [](int x, int y) {
        return rgba{uint8_t(x * 255 / 640), uint8_t(y * 255 / 480), 128, 255};
    });
    // An orientation is written as EXIF, which the thumbnail must not carry.
    vips_image_set_int(photo.get(), "orientation", 1);
    auto jpeg = save(photo.get(), ".jpg");
    REQUIRE(has_marker(jpeg, 0xE1));

    auto out = thumb(jpeg, 128);
    REQUIRE(out);
    REQUIRE(out->size() > 2);
    CHECK((*out)[0] == std::byte{0xFF});
    CHECK((*out)[1] == std::byte{0xD8});
    CHECK_FALSE(has_marker(*out, 0xE1));  // APP1: EXIF or XMP
    CHECK_FALSE(has_marker(*out, 0xE2));  // APP2: ICC
    CHECK_FALSE(has_marker(*out, 0xFE));  // COM

    auto img = decode_jpeg(*out);
    CHECK(img->Xsize == 171);
    CHECK(img->Ysize == 128);
    CHECK(img->Bands == 3);
}

TEST_CASE("thumbnail converts a wide-gamut picture to sRGB", "[image][thumbnail]") {
    // sRGB's pure red, in Display P3's numbers: drawn as if they were sRGB, a duller red.
    auto photo = draw(64, 64, [](int, int) { return rgba{234, 51, 35, 255}; });
    VipsBlob* p3;
    REQUIRE(vips_profile_load("p3", &p3, nullptr) == 0);
    REQUIRE(p3);
    size_t len;
    auto* icc = vips_blob_get(p3, &len);
    vips_image_set_blob_copy(photo.get(), VIPS_META_ICC_NAME, icc, len);
    vips_area_unref(VIPS_AREA(p3));
    auto jpeg = save(photo.get(), ".jpg");
    REQUIRE(has_marker(jpeg, 0xE2));

    auto out = thumb(jpeg, 32);
    REQUIRE(out);
    CHECK_FALSE(has_marker(*out, 0xE2));
    auto img = decode_jpeg(*out);
    CHECK(near(pixel(img.get(), 16, 16), RED, 8));
}

TEST_CASE("thumbnail is the edge tall and never upscales", "[image][thumbnail]") {
    auto size_of = [](const std::optional<std::vector<std::byte>>& jpeg) {
        REQUIRE(jpeg);
        auto img = decode_jpeg(*jpeg);
        return std::pair{img->Xsize, img->Ysize};
    };
    auto picture = [](int w, int h, const char* suffix = ".jpg") {
        return save(draw(w, h, [](int, int) { return BLUE; }).get(), suffix);
    };
    using size = std::pair<int, int>;

    auto landscape = picture(2000, 1500);
    CHECK(size_of(thumb(landscape, 300)) == size{400, 300});
    CHECK(size_of(thumb(picture(1500, 2000), 300)) == size{225, 300});
    CHECK(size_of(thumb(picture(1000, 1000), 300)) == size{300, 300});
    // Its own size, rather than the 128 asked for.
    CHECK(size_of(thumb(picture(50, 40, ".png"), 128)) == size{50, 40});
    // A phone screenshot, about 9:19.5, is inside 21:9 and kept whole.
    CHECK(size_of(thumb(picture(900, 1950), 260)) == size{120, 260});
    // Exactly 21:9 is not cropped.
    CHECK(size_of(thumb(picture(2100, 900), 210)) == size{490, 210});

    // 4:3 at each end of the clamp, the width rounded.
    CHECK(size_of(thumb(landscape, 10)) == size{85, int(image::min_thumbnail_edge)});
    CHECK(size_of(thumb(landscape, 5000)) == size{1365, int(image::max_thumbnail_edge)});
}

TEST_CASE("thumbnail draws transparency over a checkerboard", "[image][thumbnail]") {
    // Transparent everywhere but a solid red square in the middle.
    auto png =
            save(draw(
                         256,
                         256,
                         [](int x, int y) {
                             bool middle = x >= 96 && x < 160 && y >= 96 && y < 160;
                             return middle ? RED : rgba{0, 255, 0, 0};
                         },
                         4)
                         .get(),
                 ".png");

    auto out = thumb(png, 128);
    REQUIRE(out);
    auto img = decode_jpeg(*out);
    REQUIRE(img->Xsize == 128);
    REQUIRE(img->Ysize == 128);
    REQUIRE(img->Bands == 3);

    constexpr rgba LIGHT{0xFF, 0xFF, 0xFF, 255}, DARK{0xCC, 0xCC, 0xCC, 255};
    // The centre of each 8px square, which is where JPEG's blur at the edges cannot reach.
    CHECK(near(pixel(img.get(), 4, 4), LIGHT, 12));
    CHECK(near(pixel(img.get(), 12, 4), DARK, 12));
    CHECK(near(pixel(img.get(), 4, 12), DARK, 12));
    CHECK(near(pixel(img.get(), 12, 12), LIGHT, 12));
    CHECK(near(pixel(img.get(), 124, 124), LIGHT, 12));
    // The hidden colour of transparent pixels does not show through.
    CHECK(near(pixel(img.get(), 64, 64), RED));
}

TEST_CASE("thumbnail of an animation is its first frame", "[image][thumbnail]") {
    for (const char* suffix : {".gif", ".webp"}) {
        INFO(suffix);
        auto anim = save(
                draw(80, 60, [](int, int y) { return y < 60 ? RED : BLUE; }, 3, 2).get(), suffix);
        auto out = thumb(anim, 64);
        REQUIRE(out);
        auto img = decode_jpeg(*out);
        // Its own size, being shorter than the 64 asked for.
        CHECK(img->Xsize == 80);
        CHECK(img->Ysize == 60);
        CHECK(near(pixel(img.get(), 40, 30), RED));
    }
}

TEST_CASE("thumbnail of an AVIF", "[image][thumbnail]") {
    image::Source src{image_fixtures::avif_64x48};
    auto info = image::probe(src);
    REQUIRE(info);
    REQUIRE(info->format == image::Format::avif);

    auto out = thumb(image_fixtures::avif_64x48, 128);
    REQUIRE(out);
    auto img = decode_jpeg(*out);
    // Its own size, rather than the 128 asked for.
    CHECK(img->Xsize == 64);
    CHECK(img->Ysize == 48);
    CHECK(img->Bands == 3);
}

#ifdef __APPLE__
TEST_CASE("thumbnail of a HEIC decoded by ImageIO", "[image][thumbnail]") {
    REQUIRE(image::can_decode(image::Format::heic));

    auto out = thumb(image_fixtures::heic_p3_rotated, 128);
    REQUIRE(out);
    CHECK_FALSE(has_marker(*out, 0xE1));
    CHECK_FALSE(has_marker(*out, 0xE2));
    CHECK_FALSE(has_marker(*out, 0xFE));
    auto img = decode_jpeg(*out);
    // Its own size, displayed upright, rather than the 128 asked for.
    CHECK(img->Xsize == 48);
    CHECK(img->Ysize == 64);
    CHECK(img->Bands == 3);
    CHECK(img->BandFmt == VIPS_FORMAT_UCHAR);
    // Upright, and in sRGB's numbers: left as P3's, the red and green would be off by 50 or more.
    constexpr rgba WHITE{255, 255, 255, 255};
    CHECK(near(pixel(img.get(), 12, 16), BLUE));
    CHECK(near(pixel(img.get(), 36, 16), RED));
    CHECK(near(pixel(img.get(), 12, 48), WHITE));
    CHECK(near(pixel(img.get(), 36, 48), GREEN));
}
#else
TEST_CASE("thumbnail refuses HEIC without an HEVC decoder", "[image][thumbnail]") {
    bool libheif_hevc = heif_have_decoder_for_format(heif_compression_HEVC);
    CHECK(image::can_decode(image::Format::heic) == libheif_hevc);
    if (!libheif_hevc)
        CHECK_FALSE(thumb(image_fixtures::heic_p3_rotated, 128));
}
#endif

TEST_CASE("thumbnail applies EXIF orientation", "[image][thumbnail]") {
    // Stored 400x200, red on the left and blue on the right.
    auto stored = draw(400, 200, [](int x, int) { return x < 200 ? RED : BLUE; });

    SECTION("upright") {
        auto out = thumb(save(stored.get(), ".jpg"), 64);
        REQUIRE(out);
        auto img = decode_jpeg(*out);
        CHECK(img->Xsize == 128);
        CHECK(img->Ysize == 64);
        CHECK(near(pixel(img.get(), 16, 32), RED));
        CHECK(near(pixel(img.get(), 112, 32), BLUE));
    }

    SECTION("orientation 6: displayed a quarter turn clockwise, so the left edge is on top") {
        vips_image_set_int(stored.get(), "orientation", 6);
        auto out = thumb(save(stored.get(), ".jpg"), 64);
        REQUIRE(out);
        auto img = decode_jpeg(*out);
        CHECK(img->Xsize == 32);
        CHECK(img->Ysize == 64);
        CHECK(near(pixel(img.get(), 16, 8), RED));
        CHECK(near(pixel(img.get(), 16, 56), BLUE));
    }

    SECTION("orientation 8: displayed a quarter turn anticlockwise, so the left edge is below") {
        vips_image_set_int(stored.get(), "orientation", 8);
        auto out = thumb(save(stored.get(), ".jpg"), 64);
        REQUIRE(out);
        auto img = decode_jpeg(*out);
        CHECK(img->Xsize == 32);
        CHECK(img->Ysize == 64);
        CHECK(near(pixel(img.get(), 16, 8), BLUE));
        CHECK(near(pixel(img.get(), 16, 56), RED));
    }
}

TEST_CASE("thumbnail of a panorama is its centre at 21:9", "[image][thumbnail]") {
    // 100:1, green only across the middle 233 pixels: the 21:9 the crop keeps of a 100-pixel side.
    auto green_middle = [](int along) { return along >= 4884 && along < 5117 ? GREEN : RED; };
    for (bool wide : {true, false}) {
        INFO((wide ? "wide" : "tall"));
        auto pano =
                save((wide ? draw(10000, 100, [&](int x, int) { return green_middle(x); })
                           : draw(100, 10000, [&](int, int y) { return green_middle(y); }))
                             .get(),
                     ".png");
        auto out = thumb(pano, 64);
        REQUIRE(out);
        auto img = decode_jpeg(*out);
        // 64 tall; wide, 64 x 233/100 rounded, and tall, 64 x 100/233.
        CHECK(img->Xsize == (wide ? 149 : 27));
        CHECK(img->Ysize == 64);
        int w = img->Xsize - 1, h = img->Ysize - 1;
        for (auto [x, y] :
             {std::pair{4, 4}, {w - 4, 4}, {4, h - 4}, {w - 4, h - 4}, {w / 2, h / 2}})
            CHECK(near(pixel(img.get(), x, y), GREEN, 40));
    }
}

TEST_CASE("thumbnail refuses what it will not decode", "[image][thumbnail]") {
    std::string_view text = "not an image";
    CHECK_FALSE(thumb(std::as_bytes(std::span{text}), 128));

    std::string_view svg = R"(<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4"/>)";
    CHECK_FALSE(thumb(std::as_bytes(std::span{svg}), 128));

    // A JPEG whose header claims 20000x20000: 400 million pixels, over max_frame_pixels.
    auto jpeg = save(draw(64, 48, [](int, int) { return RED; }).get(), ".jpg");
    const std::array<std::byte, 2> sof0{std::byte{0xFF}, std::byte{0xC0}};
    auto sof = std::search(jpeg.begin(), jpeg.end(), sof0.begin(), sof0.end());
    REQUIRE(sof != jpeg.end());
    for (int i : {5, 7}) {
        sof[i] = std::byte{20000 >> 8};
        sof[i + 1] = std::byte{20000 & 0xff};
    }
    CHECK_FALSE(thumb(jpeg, 128));
}

TEST_CASE("thumbnail reads an encrypted file", "[image][thumbnail]") {
    auto png = save(draw(300, 200, [](int, int) { return BLUE; }).get(), ".png");
    auto seed = session::random::random(32);
    temp_file f;
    auto key = session::attachment::encrypt(
            std::as_bytes(std::span{seed}), png, session::attachment::Domain::ATTACHMENT, f.path);
    image::Source src{f.path, key};
    auto out = image::thumbnail(src, 100);
    REQUIRE(out);
    auto img = decode_jpeg(*out);
    CHECK(img->Xsize == 150);
    CHECK(img->Ysize == 100);
    CHECK(near(pixel(img.get(), 75, 50), BLUE));
}

// Not run by default: `testAll "[thumbnail-bench]"`.  What drawing transparency over the
// checkerboard costs against a plain white flatten, on a large transparent PNG and on a 12 MP JPEG
// (which has no alpha, so the two should be the same and this measures the thumbnail itself).
TEST_CASE("thumbnail backdrop benchmark", "[.][thumbnail-bench]") {
    using clock = std::chrono::steady_clock;
    auto noisy = [](int bands) {
        return [bands](int x, int y) {
            auto h = uint32_t(x) * 2654435761u ^ uint32_t(y) * 2246822519u;
            return rgba{
                    uint8_t(h),
                    uint8_t(h >> 8),
                    uint8_t(x ^ y),
                    uint8_t(bands == 4 ? (x + y) % 256 : 255)};
        };
    };
    struct input {
        const char* name;
        std::vector<std::byte> bytes;
    };
    std::vector<input> inputs;
    inputs.push_back({"4000x3000 RGBA PNG", save(draw(4000, 3000, noisy(4), 4).get(), ".png")});
    inputs.push_back({"4000x3000 JPEG", save(draw(4000, 3000, noisy(3)).get(), ".jpg")});

    constexpr int RUNS = 5;
    for (const auto& in : inputs)
        for (uint32_t edge : {240u, 480u, 1024u})
            for (auto backdrop :
                 {image::detail::Backdrop::checkerboard, image::detail::Backdrop::white}) {
                std::vector<double> ms;
                for (int i = 0; i < RUNS; i++) {
                    image::Source src{in.bytes};
                    auto start = clock::now();
                    auto out = image::detail::thumbnail(src, edge, backdrop);
                    ms.push_back(std::chrono::duration<double, std::milli>(clock::now() - start)
                                         .count());
                    REQUIRE(out);
                }
                std::ranges::sort(ms);
                std::printf(
                        "%-20s edge %4u %-12s median %8.1f ms  min %8.1f ms\n",
                        in.name,
                        edge,
                        backdrop == image::detail::Backdrop::checkerboard ? "checkerboard"
                                                                          : "white",
                        ms[RUNS / 2],
                        ms[0]);
            }
}

TEST_CASE(
        "thumbnail refuses an image decoded whole over max_whole_decode_bytes",
        "[image][thumbnail]") {
    // Solid, so that something this size encodes quickly.
    auto solid = [](int w, int h) {
        image::init();
        VipsImage* black;
        REQUIRE(vips_black(&black, w, h, "bands", 3, nullptr) == 0);
        image_ptr b{black};
        VipsImage* srgb;
        REQUIRE(vips_copy(black, &srgb, "interpretation", VIPS_INTERPRETATION_sRGB, nullptr) == 0);
        return image_ptr{srgb};
    };
    // A progressive JPEG costs 2 bytes a coefficient, shrunk by 8 to a thumbnail: at 4:4:4 that is
    // 6 bytes a pixel, about 58 MP.
    auto under = solid(6400, 6400), over = solid(7800, 7800);
    CHECK(thumb(save(under.get(), ".jpg[interlace,subsample_mode=off]"), 64));
    CHECK_FALSE(thumb(save(over.get(), ".jpg[interlace,subsample_mode=off]"), 64));
    // A baseline JPEG shrinks as it decodes, so its size is no reason to refuse it.
    CHECK(thumb(save(over.get(), ".jpg[subsample_mode=off]"), 64));

    // 16 bits a sample cost 10 bytes a pixel against 8 bits' 6: 36 MP is over one, not the other.
    VipsImage *black, *deep, *grey;
    REQUIRE(vips_black(&black, 6000, 6000, nullptr) == 0);
    image_ptr b{black};
    REQUIRE(vips_cast_ushort(black, &deep, nullptr) == 0);
    image_ptr d{deep};
    REQUIRE(vips_copy(deep, &grey, "interpretation", VIPS_INTERPRETATION_GREY16, nullptr) == 0);
    image_ptr g{grey};
    CHECK_FALSE(thumb(save(grey, ".png[interlace]"), 64));

    // AVIF at 15 bytes a pixel, about 23 MP, and at 27 over 8 bits.
    REQUIRE(image::can_decode(image::Format::avif));
    CHECK_FALSE(thumb(image_fixtures::avif8_4900x4900, 64));
    image::Source src{image_fixtures::avif10_3700x3700};
    auto info = image::probe(src);
    REQUIRE(info);
    CHECK(info->bits_per_sample == 16);
    CHECK_FALSE(thumb(image_fixtures::avif10_3700x3700, 64));
}

TEST_CASE(
        "a progressive JPEG's output is costed at the shrink a cover or a fit would load it at",
        "[image][thumbnail]") {
    // Tall: a cover to 256 is bound by the 2000 side, shrinking by 2; a fit by 16000, by 8.
    image::Info info{};
    info.format = image::Format::jpeg;
    info.width = 2000;
    info.height = 16000;
    info.frames = 1;
    info.orientation = 1;
    info.decoded_whole = true;
    info.bits_per_sample = 8;
    info.decodable = true;
    info.bands = 3;
    // Room for the output at 1/8 (1.5 MB) and not at 1/2 (24 MB).
    info.coefficient_bytes = image::max_whole_decode_bytes - (10 << 20);
    CHECK(image::detail::acceptable(info, 256, false));
    CHECK_FALSE(image::detail::acceptable(info, 256, true));
}

TEST_CASE("thumbhash::of_picture hashes a scaled-down, upright picture", "[image][thumbhash]") {
    auto photo = draw(640, 480, [](int x, int) { return x < 320 ? RED : BLUE; });
    vips_image_set_int(photo.get(), "orientation", 6);
    auto jpeg = save(photo.get(), ".jpg");
    image::Source src{jpeg};

    auto hash = image::thumbhash::of_picture(src);
    REQUIRE(hash);
    CHECK(hash->size() <= image::thumbhash::max_hash_size);
    REQUIRE(image::thumbhash::valid(*hash));

    // Upright: a quarter turn makes the picture taller than wide, and puts red on top.
    CHECK(image::thumbhash::component_aspect_ratio(*hash) < 1.0);
    auto img = image::thumbhash::decode(*hash, 24, 32);
    auto px = [&](int x, int y) {
        auto* p = reinterpret_cast<const uint8_t*>(img.rgba.data()) + (size_t(y) * 24 + x) * 4;
        return rgba{p[0], p[1], p[2], 255};
    };
    CHECK(near(px(12, 4), RED, 80));
    CHECK(near(px(12, 28), BLUE, 80));

    std::vector<std::byte> pdf{std::byte{'%'}, std::byte{'P'}, std::byte{'D'}, std::byte{'F'}};
    image::Source bad{pdf};
    CHECK_FALSE(image::thumbhash::of_picture(bad));
}
