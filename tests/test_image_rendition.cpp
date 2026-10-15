#include <vips/vips.h>

#include <catch2/catch_test_macros.hpp>
#include <optional>
#include <session/image/probe.hpp>
#include <session/image/rendition.hpp>
#include <session/image/thumbnail.hpp>
#include <vector>

#include "image_drawing.hpp"
#include "image_fixtures.hpp"

namespace image = session::image;
using image_test::rgba;

namespace {

using namespace image_test;

std::optional<std::vector<std::byte>> render(std::span<const std::byte> data, uint32_t edge) {
    image::Source src{data};
    return image::rendition(src, edge);
}

std::pair<int, int> size_of(const std::optional<std::vector<std::byte>>& jpeg) {
    REQUIRE(jpeg);
    auto img = decode_jpeg(*jpeg);
    return {img->Xsize, img->Ysize};
}

}  // namespace

TEST_CASE("rendition fits the whole picture inside the edge", "[image][rendition]") {
    auto landscape = save(draw(2000, 1500, [](int, int) { return BLUE; }).get(), ".jpg");
    auto portrait = save(draw(600, 1600, [](int, int) { return RED; }).get(), ".png");
    CHECK(size_of(render(landscape, 1000)) == std::pair{1000, 750});
    CHECK(size_of(render(portrait, 800)) == std::pair{300, 800});

    // The whole of it, not its centre: both ends of the long side are still there.
    auto striped =
            save(draw(1200,
                      400,
                      [](int x, int) {
                          return x < 400 ? RED : x < 800 ? GREEN : BLUE;
                      }).get(),
                 ".png");
    auto out = render(striped, 600);
    REQUIRE(size_of(out) == std::pair{600, 200});
    auto img = decode_jpeg(*out);
    CHECK(near(pixel(img.get(), 50, 100), RED));
    CHECK(near(pixel(img.get(), 300, 100), GREEN));
    CHECK(near(pixel(img.get(), 550, 100), BLUE));
}

TEST_CASE("rendition edge is clamped and never upscales", "[image][rendition]") {
    auto big = save(draw(8000, 6000, [](int, int) { return BLUE; }).get(), ".jpg");
    auto small = save(draw(300, 200, [](int, int) { return BLUE; }).get(), ".png");
    CHECK(size_of(render(big, 10)).first == int(image::min_rendition_edge));
    CHECK(size_of(render(big, 100000)).first == int(image::max_rendition_edge));
    CHECK(size_of(render(big, 1200)) == std::pair{1200, 900});
    // Its own size, rather than the 1000 asked for.
    CHECK(size_of(render(small, 1000)) == std::pair{300, 200});
}

TEST_CASE("rendition applies EXIF orientation and carries no metadata", "[image][rendition]") {
    auto photo = draw(640, 480, [](int x, int y) {
        return rgba{uint8_t(x * 255 / 640), uint8_t(y * 255 / 480), 128, 255};
    });
    // A quarter turn clockwise, as a camera held upright stores a landscape sensor's frame.
    vips_image_set_int(photo.get(), "orientation", 6);
    auto jpeg = save(photo.get(), ".jpg");
    REQUIRE(has_marker(jpeg, 0xE1));

    auto out = render(jpeg, 1000);
    CHECK(size_of(out) == std::pair{480, 640});
    CHECK_FALSE(has_marker(*out, 0xE1));
    CHECK_FALSE(has_marker(*out, 0xE2));
    CHECK_FALSE(has_marker(*out, 0xFE));
}

TEST_CASE("rendition draws transparency over a checkerboard", "[image][rendition]") {
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
    auto out = render(png, 1000);
    REQUIRE(size_of(out) == std::pair{256, 256});
    auto img = decode_jpeg(*out);
    constexpr rgba LIGHT{0xFF, 0xFF, 0xFF, 255}, DARK{0xCC, 0xCC, 0xCC, 255};
    CHECK(near(pixel(img.get(), 4, 4), LIGHT, 12));
    CHECK(near(pixel(img.get(), 12, 4), DARK, 12));
    CHECK(near(pixel(img.get(), 128, 128), RED));
}

TEST_CASE("rendition of an animation is its first frame", "[image][rendition]") {
    for (const char* suffix : {".gif", ".webp"}) {
        INFO(suffix);
        auto anim = save(
                draw(80, 60, [](int, int y) { return y < 60 ? RED : BLUE; }, 3, 2).get(), suffix);
        auto out = render(anim, 1000);
        REQUIRE(size_of(out) == std::pair{80, 60});
        CHECK(near(pixel(decode_jpeg(*out).get(), 40, 30), RED));
    }
}

TEST_CASE("rendition refuses what thumbnail refuses", "[image][rendition]") {
    std::vector<std::byte> pdf{std::byte{'%'}, std::byte{'P'}, std::byte{'D'}, std::byte{'F'}};
    CHECK_FALSE(render(pdf, 1000));
    // Over the whole-decode budget, as the thumbnail test establishes for this fixture.
    CHECK_FALSE(render(image_fixtures::avif8_4900x4900, 1000));
}
