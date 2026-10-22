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

bool told_refused(Fixture& f, int64_t id) {
    for (const auto& m : Recorder::messages(f.rec.msg_updated))
        if (m.id == id && m.attachments[0].picture && m.attachments[0].picture->rendition_refused)
            return true;
    return false;
}

}  // namespace

TEST_CASE("Client: a rendition is made when first asked for, and kept", "[client][rendition]") {
    Fixture f;
    // A PNG, so the rendition is a copy of its own rather than the original itself.
    auto [id, url] = f.arrive(picture(1600, 1200));
    settle(*f.c);
    REQUIRE(f.attachment(id).has_thumbnail);
    CHECK_FALSE(f.attachment(id).has_rendition);
    CHECK_FALSE(std::filesystem::exists(view_file(f, url)));

    f.rec.msg_updated.clear();
    CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
    settle(*f.c);
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
    settle(*f.c);
    CHECK(f.db_get("SELECT count(*) FROM attachment_derived WHERE kind = ?", rendition_kind) == 0);
}

TEST_CASE("Client: a picture no rendition can be made of is refused once", "[client][rendition]") {
    Fixture f;
    f.rec.msg_updated.clear();
    // Labelled a picture, so a thumbnail is attempted and refused; the rendition likewise, from
    // the same reading of its header, and said before anyone asks.
    auto [bad, url] = f.arrive(std::vector<std::byte>(600, std::byte{7}), "image/png");
    CHECK_FALSE(f.attachment(bad).has_thumbnail);
    CHECK(f.attachment(bad).picture->rendition_refused);
    CHECK(told_refused(f, bad));
    CHECK(error_code([&] { f.c->attachment_rendition(bad, 0, await); }) == err::no_rendition);
    CHECK(TestHelper::thumbnails_queued(*f.c) == 0);
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

TEST_CASE("Client: asking twice for one rendition queues it once", "[client][rendition]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    TestHelper::stall_thumbnails(*f.c);
    CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
    CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
    CHECK(TestHelper::thumbnails_queued(*f.c) == 1);
    TestHelper::resume_thumbnails(*f.c);
    settle(*f.c);
    CHECK(f.attachment(id).has_rendition);
    CHECK(TestHelper::thumbnails_queued(*f.c) == 0);
}

TEST_CASE("Client: a rendition whose decode fails is refused, and said", "[client][rendition]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    auto refused = [&] {
        return f.db_get(
                "SELECT coalesce((SELECT failed FROM attachment_derived d WHERE d.entry = c.id"
                " AND d.kind = ?), 0) FROM attachment_cache c WHERE c.name = ?",
                rendition_kind,
                f.file(url).filename().string());
    };

    // The cached file damaged from outside, so that reading it throws rather than refuses.  The
    // viewer that asked is waiting, so it is told at once rather than left to ask again.
    std::vector<std::byte> junk(3000);
    random::fill(junk);
    overwrite(f.file(url), junk);
    f.rec.msg_updated.clear();
    CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
    settle(*f.c);
    CHECK(refused() == image::renderer_version);
    CHECK(told_refused(f, id));

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
        // Kept across a restart: the sweep looks for no file behind it.
        f.reopen();
        CHECK(f.attachment(id).has_rendition);
        CHECK(f.c->attachment_rendition(id, 0, await) == photo);
    }

    SECTION("a large one is drawn at the default edge") {
        auto [id, url] = f.arrive(picture(4000, 3000));
        CHECK(jpeg_size(ask_until_made(f, id)) == std::pair{2048, 1536});
    }

    SECTION("one sent as its original file gets a thumbnail and no rendition") {
        auto [id, url] = f.arrive(
                picture(400, 300),
                "image/png",
                true,
                SessionProtos::AttachmentPointer::ORIGINAL_FILE);
        settle(*f.c);
        CHECK(f.attachment(id).has_thumbnail);
        CHECK_FALSE(f.attachment(id).has_rendition);
        CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
        settle(*f.c);
        CHECK(f.db_get("SELECT count(*) FROM attachment_derived WHERE kind = ?", rendition_kind) ==
              0);
    }

    SECTION("a content type's parameters, case and spacing change nothing") {
        auto photo = picture(400, 300, ".jpg");
        auto [jpeg, jpeg_url] = f.arrive(photo, "IMAGE/JPEG; charset=binary");
        auto [png, png_url] = f.arrive(picture(400, 300), " image/png ; foo=bar");
        settle(*f.c);
        CHECK(f.attachment(jpeg).has_thumbnail);
        CHECK(f.attachment(png).has_thumbnail);
        CHECK(f.attachment(jpeg).has_rendition);
        CHECK(f.c->attachment_rendition(jpeg, 0, await) == photo);
        CHECK(jpeg_size(ask_until_made(f, png)) == std::pair{400, 300});
    }

    SECTION("a type that only starts like one Session displays gets neither") {
        auto [id, url] = f.arrive(picture(400, 300, ".jpg"), "image/jpeg2000");
        settle(*f.c);
        CHECK_FALSE(f.attachment(id).has_thumbnail);
        CHECK_FALSE(f.attachment(id).has_rendition);
    }

    SECTION("an original that cannot be read takes its entry with it") {
        auto [id, url] = f.arrive(picture(400, 300, ".jpg"), "image/jpeg");
        settle(*f.c);
        REQUIRE(f.attachment(id).has_rendition);
        std::vector<std::byte> junk(3000);
        random::fill(junk);
        overwrite(f.file(url), junk);
        CHECK(error_code([&] { f.c->attachment_rendition(id, 0, await); }) == err::no_rendition);
        CHECK(f.db_get("SELECT count(*) FROM attachment_cache") == 0);
        CHECK_FALSE(f.attachment(id).has_rendition);
    }
}

namespace {

// Delivers `pictures` as the PNG attachments of one message, lets them download, and returns its
// id and their urls.
std::pair<int64_t, std::vector<std::string>> arrive_together(
        Fixture& f, const std::vector<std::vector<std::byte>>& pictures) {
    std::vector<std::string> urls, keys;
    for (const auto& data : pictures) {
        auto [ct, key] = attachment::encrypt(f.seed, data, attachment::Domain::ATTACHMENT);
        auto file_id = "f{}-{}"_format(f.sent, urls.size());
        f.net->served[file_id] = ct;
        urls.push_back(network::file_server::generate_download_url(file_id, {}, true));
        keys.emplace_back(reinterpret_cast<const char*>(key.data()), key.size());
    }
    deliver(*f.c,
            f.peer,
            "",
            from_epoch_ms(1000 + f.sent),
            "h{}"_format(f.sent),
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                for (size_t i = 0; i < pictures.size(); i++) {
                    auto* a = d.add_attachments();
                    a->set_id(i + 1);
                    a->set_url(urls[i]);
                    a->set_key(keys[i]);
                    a->set_size(pictures[i].size());
                    a->set_contenttype("image/png");
                }
            });
    f.sent++;
    size_t served = 0;
    REQUIRE(eventually([&] {
        sync(*f.c);
        served += serve_downloads(*f.net);
        return served == pictures.size();
    }));
    settle(*f.c);
    return {f.c->conversation(f.convo, await)->messages(await)[0].id, urls};
}

}  // namespace

TEST_CASE(
        "Client: asking for one rendition queues its message's others behind it",
        "[client][rendition]") {
    Fixture f;
    auto [alone, alone_url] = f.arrive(picture(400, 300));
    auto [id, urls] = arrive_together(f, {picture(400, 300), picture(500, 300), picture(600, 300)});
    auto has_rendition = [&](size_t i) {
        return f.c->message(id, await)->attachments.at(i).has_rendition;
    };
    for (size_t i = 0; i < urls.size(); i++)
        CHECK_FALSE(has_rendition(i));

    TestHelper::stall_thumbnails(*f.c);
    CHECK(error_code([&] { f.c->attachment_rendition(id, 1, await); }) == err::no_rendition);
    CHECK(TestHelper::thumbnails_pending(*f.c) ==
          std::vector{f.entry(urls[1]), f.entry(urls[0]), f.entry(urls[2])});
    TestHelper::resume_thumbnails(*f.c);
    settle(*f.c);
    for (size_t i = 0; i < urls.size(); i++)
        CHECK(has_rendition(i));
    CHECK_FALSE(f.attachment(alone).has_rendition);

    // Asking again for one already made queues nothing.
    CHECK_FALSE(f.c->attachment_rendition(id, 0, await).empty());
    CHECK(TestHelper::thumbnails_queued(*f.c) == 0);
}
