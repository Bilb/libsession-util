#include <session/image/rendition.hpp>

#include "derived_fixture.hpp"

using namespace derived_test;

namespace {

constexpr auto rendition_kind = static_cast<int>(cache::Derived::rendition);

std::filesystem::path view_file(Fixture& f, const std::string& url) {
    auto p = f.file(url);
    p += cache::derived_suffix(cache::Derived::rendition);
    return p;
}

// Asks until the rendition is served, as a viewer told through messages_updated would.
std::vector<std::byte> ask_until_made(Fixture& f, int64_t id) {
    std::vector<std::byte> got;
    REQUIRE(eventually([&] {
        try {
            got = f.c->attachment_rendition(id, 0, await);
            return true;
        } catch (const session::error&) {
            return false;
        }
    }));
    return got;
}

}  // namespace

TEST_CASE("Client: a rendition is made once a picture is cached, and kept", "[client][rendition]") {
    Fixture f;
    f.rec.msg_updated.clear();
    // A PNG, so the rendition is a copy of its own rather than the original itself.
    auto [id, url] = f.arrive(picture(1600, 1200));
    settle(*f.c);
    REQUIRE(f.attachment(id).has_thumbnail);
    CHECK(f.attachment(id).has_rendition);
    bool told = false;
    for (const auto& m : Recorder::messages(f.rec.msg_updated))
        if (m.id == id && m.attachments[0].has_rendition)
            told = true;
    CHECK(told);

    // Then served, from a file beside the original, counted with it.
    auto jpeg = f.c->attachment_rendition(id, 0, await);
    CHECK(jpeg_size(jpeg) == std::pair{1600, 1200});
    CHECK(std::filesystem::exists(view_file(f, url)));
    auto entry = f.entry(url);
    auto size = f.db_get(
            "SELECT size FROM attachment_derived WHERE entry = ? AND kind = ?",
            entry,
            rendition_kind);
    CHECK(size == static_cast<int64_t>(std::filesystem::file_size(view_file(f, url))));
    CHECK(f.c->attachment_cache_size(await) ==
          f.db_get("SELECT size FROM attachment_cache WHERE id = ?", entry) + size +
                  f.db_get(
                          "SELECT size FROM attachment_derived WHERE entry = ? AND kind = 1",
                          entry));

    // Asking again decodes nothing: the file is read back as it is.
    CHECK(TestHelper::thumbnails_queued(*f.c) == 0);
    CHECK(f.c->attachment_rendition(id, 0, await) == jpeg);
    CHECK(TestHelper::thumbnails_queued(*f.c) == 0);

    // The handler form answers the same.
    std::promise<Expected<std::vector<std::byte>>> got;
    f.c->attachment_rendition(id, 0, [&](auto r) { got.set_value(std::move(r)); });
    auto r = got.get_future().get();
    REQUIRE(r);
    CHECK(*r == jpeg);
}

TEST_CASE("Client: a rendition fits the rendition edge and never upscales", "[client][rendition]") {
    Fixture f{default_rendition_edge{800}};
    auto [big, big_url] = f.arrive(picture(1600, 1200, ".jpg"));
    auto [small, small_url] = f.arrive(picture(300, 200));
    CHECK(f.c->rendition_edge(await) == 800);
    CHECK(jpeg_size(ask_until_made(f, big)) == std::pair{800, 600});
    CHECK(jpeg_size(ask_until_made(f, small)) == std::pair{300, 200});

    // A stored edge wins over the constructor's, is clamped, and applies to new ones only.
    f.c->set_rendition_edge(100000, await);
    CHECK(f.c->rendition_edge(await) == image::max_rendition_edge);
    f.c->set_rendition_edge(1000, await);
    auto [later, later_url] = f.arrive(picture(1600, 1200, ".jpg"));
    CHECK(jpeg_size(ask_until_made(f, later)) == std::pair{1000, 750});
    CHECK(jpeg_size(f.c->attachment_rendition(big, 0, await)) == std::pair{800, 600});
    f.c->set_rendition_edge(std::nullopt, await);
    CHECK(f.c->rendition_edge(await) == 800);
}

TEST_CASE("Client: nothing has a rendition before it could", "[client][rendition]") {
    ScopedClockOffset clock{0s};
    Fixture f;
    auto [pdf, pdf_url] = f.arrive(std::vector<std::byte>(500, std::byte{1}), "application/pdf");
    CHECK(error_code([&] { f.c->attachment_rendition(pdf, 0, await); }) == err::no_rendition);
    CHECK(TestHelper::thumbnails_queued(*f.c) == 0);

    auto [id, url] = f.arrive(picture(400, 300));
    CHECK(error_code([&] { f.c->attachment_rendition(id, 1, await); }) ==
          err::attachment_not_found);
    CHECK(error_code([&] { f.c->attachment_rendition(id + 1000, 0, await); }) ==
          err::message_not_found);

    // Not cached: nothing to make it from, and nothing is fetched to.
    AdjustedClock::set_offset(1s);
    f.c->set_attachment_cache_limit(1, await);
    auto [later, later_url] = f.arrive(picture(300, 200));
    REQUIRE(f.attachment(id).availability == AttachmentAvailability::absent);
    auto fetched = f.net->downloads.size();
    CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
    sync(*f.c);
    CHECK(TestHelper::thumbnails_queued(*f.c) == 0);
    CHECK(f.net->downloads.size() == fetched);
}

TEST_CASE(
        "Client: a rendition goes with its entry, and is remade if found missing",
        "[client][rendition][evict]") {
    ScopedClockOffset clock{0s};
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    ask_until_made(f, id);
    REQUIRE(std::filesystem::exists(view_file(f, url)));

    // Deleted from under it: forgotten, reported, and made again on the next ask.
    std::filesystem::remove(view_file(f, url));
    f.rec.msg_updated.clear();
    CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
    settle(*f.c);
    CHECK(f.attachment(id).has_rendition);
    CHECK(std::filesystem::exists(view_file(f, url)));

    // Evicted with the file: the next arrival pushes it out, rows and files.
    AdjustedClock::set_offset(1s);
    f.c->set_attachment_cache_limit(1, await);
    auto [later, later_url] = f.arrive(picture(300, 200));
    CHECK_FALSE(f.attachment(id).has_rendition);
    CHECK_FALSE(std::filesystem::exists(view_file(f, url)));
    CHECK_FALSE(std::filesystem::exists(f.thumb_file(url)));
    // The later picture's own is all that is left.
    settle(*f.c);
    CHECK(f.db_get("SELECT count(*) FROM attachment_derived WHERE kind = ?", rendition_kind) == 1);
}

TEST_CASE("Client: a picture no rendition can be made of is refused once", "[client][rendition]") {
    Fixture f;
    // Labelled a picture, so a thumbnail is attempted and refused; the rendition likewise.
    auto [bad, url] = f.arrive(std::vector<std::byte>(600, std::byte{7}), "image/png");
    CHECK_FALSE(f.attachment(bad).has_thumbnail);
    CHECK(error_code([&] { f.c->attachment_rendition(bad, 0, await); }) == err::no_rendition);
    settle(*f.c);
    CHECK_FALSE(f.attachment(bad).has_rendition);
    auto refused = f.db_get(
            "SELECT coalesce((SELECT failed FROM attachment_derived d WHERE d.entry = c.id"
            " AND d.kind = ?), 0) FROM attachment_cache c WHERE c.name = ?",
            rendition_kind,
            f.file(url).filename().string());
    CHECK(refused == image::renderer_version);
    REQUIRE(f.attachment(bad).picture);
    CHECK_FALSE(f.attachment(bad).picture->readable());
    CHECK(f.attachment(bad).picture->rendition_refused);

    // Not tried again when asked again...
    CHECK(error_code([&] { f.c->attachment_rendition(bad, 0, await); }) == err::no_rendition);
    CHECK(TestHelper::thumbnails_queued(*f.c) == 0);

    // ...until the renderer is newer than the refusal.
    TestHelper::on_loop(f.c->core, [&] {
        f.c->core.database().conn().prepared_exec(
                "UPDATE attachment_derived SET failed = failed - 1 WHERE kind = ?", rendition_kind);
    });
    CHECK(error_code([&] { f.c->attachment_rendition(bad, 0, await); }) == err::no_rendition);
    settle(*f.c);
    CHECK(f.db_get("SELECT failed FROM attachment_derived WHERE kind = ?", rendition_kind) ==
          image::renderer_version);
}

namespace {

// Removes a made rendition, rows and file, as a picture cached before renditions were made on
// arrival would be: only an ask makes one then.
void forget_rendition(Fixture& f, const std::string& url) {
    settle(*f.c);
    std::filesystem::remove(view_file(f, url));
    TestHelper::on_loop(f.c->core, [&] {
        f.c->core.database().conn().prepared_exec(
                "DELETE FROM attachment_derived WHERE kind = ?", rendition_kind);
    });
}

}  // namespace

TEST_CASE("Client: asking twice for one rendition queues it once", "[client][rendition]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    forget_rendition(f, url);
    TestHelper::stall_thumbnails(*f.c);
    CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
    CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
    CHECK(TestHelper::thumbnails_queued(*f.c) == 1);
    TestHelper::resume_thumbnails(*f.c);
    settle(*f.c);
    CHECK(f.attachment(id).has_rendition);
    CHECK(TestHelper::thumbnails_queued(*f.c) == 0);
}

TEST_CASE("Client: a rendition whose decode fails gets one more try", "[client][rendition]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    forget_rendition(f, url);
    auto refused = [&] {
        return f.db_get(
                "SELECT coalesce((SELECT failed FROM attachment_derived d WHERE d.entry = c.id"
                " AND d.kind = ?), 0) FROM attachment_cache c WHERE c.name = ?",
                rendition_kind,
                f.file(url).filename().string());
    };

    // The cached file damaged from outside, so that reading it throws rather than refuses.
    std::vector<std::byte> junk(3000);
    random::fill(junk);
    overwrite(f.file(url), junk);
    CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
    settle(*f.c);
    CHECK(refused() == -image::renderer_version);

    // Asked again: the second strike, after which it is refused and not tried again.
    CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
    settle(*f.c);
    CHECK(refused() == image::renderer_version);
    // Turned away rather than tried: an attempt would have marked it -version again.
    CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
    settle(*f.c);
    CHECK(refused() == image::renderer_version);
}

TEST_CASE("Client: which pictures get which rendition", "[client][rendition]") {
    Fixture f;

    SECTION("one already as a viewer draws it is its own, with no copy") {
        auto photo = picture(400, 300, ".jpg");
        auto [id, url] = f.arrive(photo, "image/jpeg");
        settle(*f.c);
        CHECK(f.attachment(id).has_rendition);
        CHECK(f.c->attachment_rendition(id, 0, await) == photo);
        CHECK_FALSE(std::filesystem::exists(view_file(f, url)));
        CHECK(f.db_get("SELECT size FROM attachment_derived WHERE kind = ?", rendition_kind) == 0);
    }

    SECTION("a large one is drawn at the default edge") {
        auto [id, url] = f.arrive(picture(4000, 3000));
        settle(*f.c);
        CHECK(jpeg_size(f.c->attachment_rendition(id, 0, await)) == std::pair{2048, 1536});
    }

    SECTION("one sent as its original file gets a thumbnail and no rendition") {
        auto [id, url] = f.arrive(picture(400, 300), "image/png", true, /*ORIGINAL_FILE*/ 2);
        settle(*f.c);
        CHECK(f.attachment(id).has_thumbnail);
        CHECK_FALSE(f.attachment(id).has_rendition);
        CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
        CHECK(TestHelper::thumbnails_queued(*f.c) == 0);
    }
}
