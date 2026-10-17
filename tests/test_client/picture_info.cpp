#include <session/image/rendition.hpp>

#include "../../src/image/vips_internal.hpp"
#include "derived_fixture.hpp"
#include "image_fixtures.hpp"

using namespace derived_test;

namespace {

constexpr auto rendition_kind = static_cast<int>(cache::Derived::rendition);

}  // namespace

TEST_CASE("Client: a cached picture reports what its header says", "[client][picture]") {
    Fixture f;

    SECTION("a still picture: its size, one frame, nothing refused") {
        f.rec.msg_updated.clear();
        auto [id, url] = f.arrive(picture(400, 300));
        auto a = f.attachment(id);
        REQUIRE(a.picture);
        CHECK(a.picture->width == 400);
        CHECK(a.picture->height == 300);
        CHECK(a.picture->frames == 1);
        CHECK(a.picture->readable());
        CHECK_FALSE(a.picture->animated());
        CHECK_FALSE(a.picture->rendition_refused);

        // Reported like a thumbnail is, and once: the thumbnail's own report carries it.
        bool told = false;
        for (const auto& m : Recorder::messages(f.rec.msg_updated))
            if (m.id == id && m.attachments[0].picture)
                told = true;
        CHECK(told);
    }

    SECTION("a sideways JPEG reports its upright size, as the sender's claim need not") {
        auto [id, url] = f.arrive(picture(400, 300, ".jpg", 6), "image/jpeg");
        auto a = f.attachment(id);
        REQUIRE(a.picture);
        CHECK(a.picture->width == 300);
        CHECK(a.picture->height == 400);
        CHECK_FALSE(a.width);
    }

    SECTION("a file that is not a picture reports that it could not be read") {
        auto [id, url] = f.arrive(std::vector<std::byte>(600, std::byte{7}), "image/png");
        auto a = f.attachment(id);
        REQUIRE(a.picture);
        CHECK_FALSE(a.picture->readable());
        CHECK(a.picture->width == 0);
        CHECK(a.picture->frames == 0);
    }

    SECTION("a picture too large to decode still reports its size") {
        auto [id, url] = f.arrive(image_fixtures::avif8_4900x4900, "image/avif");
        auto a = f.attachment(id);
        CHECK_FALSE(a.has_thumbnail);
        REQUIRE(a.picture);
        CHECK(a.picture->width == 4900);
        CHECK(a.picture->height == 4900);
        CHECK(a.picture->frames == 1);
        // Its thumbnail was refused, so no rendition is queued after it; one asked for is refused.
        CHECK_FALSE(a.picture->rendition_refused);
        CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
        settle(*f.c);
        CHECK(f.attachment(id).picture->rendition_refused);
    }

    SECTION("nothing is said before the header has been read, or after the file has gone") {
        ScopedClockOffset clock{0s};
        TestHelper::stall_thumbnails(*f.c);
        auto [id, url] = f.arrive(picture(400, 300), "image/png", false);
        CHECK_FALSE(f.attachment(id).picture);
        TestHelper::resume_thumbnails(*f.c);
        settle(*f.c);
        REQUIRE(f.attachment(id).picture);

        f.reopen();
        REQUIRE(f.attachment(id).picture);
        CHECK(f.attachment(id).picture->width == 400);

        AdjustedClock::set_offset(1s);
        f.c->set_attachment_cache_limit(1, await);
        auto [later, later_url] = f.arrive(picture(300, 200));
        REQUIRE(f.attachment(id).availability == AttachmentAvailability::absent);
        CHECK_FALSE(f.attachment(id).picture);
        CHECK(f.attachment(later).picture);
    }
}

TEST_CASE("Client: an animation's rendition is animated", "[client][picture]") {
    Fixture f;
    auto suffix = GENERATE(".gif", ".webp");
    INFO(suffix);
    auto type = suffix == std::string_view{".gif"} ? "image/gif" : "image/webp";
    auto [id, url] = f.arrive(animation(60, 40, 4, suffix), type);
    auto a = f.attachment(id);
    REQUIRE(a.picture);
    CHECK(a.picture->frames == 4);
    CHECK(a.picture->animated());
    CHECK(a.picture->width == 60);
    CHECK(a.picture->height == 40);
    // The tile still gets its first frame.
    CHECK(a.has_thumbnail);

    settle(*f.c);
    REQUIRE(f.attachment(id).has_rendition);
    auto webp = f.c->attachment_rendition(id, 0, await);
    image::detail::image_ptr img{
            vips_image_new_from_buffer(webp.data(), webp.size(), "n=-1", nullptr)};
    REQUIRE(img);
    CHECK(vips_image_get_n_pages(img.get()) == 4);
}
