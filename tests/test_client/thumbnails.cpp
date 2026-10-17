#include <session/image/thumbhash.hpp>

#include "derived_fixture.hpp"

using namespace derived_test;

TEST_CASE("Client: a downloaded picture gets a thumbnail", "[client][thumbnail]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(800, 600));

    auto a = f.attachment(id);
    CHECK(a.availability == AttachmentAvailability::cached);
    CHECK(a.has_thumbnail);

    // Told, through the report every other change to the message goes through.
    bool reported = false;
    for (const auto& m : Recorder::messages(f.rec.msg_updated))
        if (m.id == id && !m.attachments.empty() && m.attachments[0].has_thumbnail)
            reported = true;
    CHECK(reported);

    // Square, at the default edge, and beside the file it was made from.
    auto jpeg = f.c->attachment_thumbnail(id, 0, await);
    CHECK(jpeg_size(jpeg) == std::pair{int(DEFAULT_THUMBNAIL_EDGE), int(DEFAULT_THUMBNAIL_EDGE)});
    REQUIRE(std::filesystem::exists(f.thumb_file(url)));

    // Encrypted like the file, so the bytes on disk are not the JPEG.
    auto on_disk = std::filesystem::file_size(f.thumb_file(url));
    CHECK(on_disk > jpeg.size());

    // One entry, counting every file made from it: the thumbnail, and the rendition after it.
    settle(*f.c);
    CHECK(f.db_get("SELECT count(*) FROM attachment_cache") == 1);
    CHECK(f.c->attachment_cache_size(await) ==
          static_cast<int64_t>(std::filesystem::file_size(f.file(url)) + on_disk) +
                  f.db_get(
                          "SELECT size FROM attachment_derived WHERE kind = ?",
                          static_cast<int>(cache::Derived::rendition)));

    // The handler form answers the same, through the dispatcher.
    std::promise<Expected<std::vector<std::byte>>> got;
    f.c->attachment_thumbnail(id, 0, [&](auto r) { got.set_value(std::move(r)); });
    auto r = got.get_future().get();
    REQUIRE(r);
    CHECK(*r == jpeg);
}

TEST_CASE("Client: only a picture gets a thumbnail", "[client][thumbnail]") {
    Fixture f;

    std::vector<std::byte> pdf(3000);
    random::fill(pdf);
    auto [doc, doc_url] = f.arrive(pdf, "application/pdf");
    // Labelled as a picture, but not one: there is nothing to make a thumbnail of.
    auto [fake, fake_url] = f.arrive(pdf, "image/png");
    // A picture, but of a type Session does not display as one.
    auto [svg, svg_url] = f.arrive(picture(100, 100), "image/svg+xml");

    for (const auto& [id, url] : std::vector<std::pair<int64_t, std::string>>{
                 {doc, doc_url}, {fake, fake_url}, {svg, svg_url}}) {
        INFO(url);
        auto a = f.attachment(id);
        CHECK(a.availability == AttachmentAvailability::cached);
        CHECK_FALSE(a.has_thumbnail);
        CHECK_FALSE(std::filesystem::exists(f.thumb_file(url)));
        CHECK(error_code([&] { f.c->attachment_thumbnail(id, 0, await); }) == err::no_thumbnail);
    }

    CHECK(error_code([&] { f.c->attachment_thumbnail(doc + 1000, 0, await); }) ==
          err::message_not_found);
    CHECK(error_code([&] { f.c->attachment_thumbnail(doc, 1, await); }) ==
          err::attachment_not_found);
}

TEST_CASE("Client: a picture that is not cached has no thumbnail", "[client][thumbnail]") {
    TempClient c;
    SenderKeys peer;
    deliver(*c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url("http://fs.example/file/111#d");
                a->set_key(std::string(32, 'k'));
                a->set_contenttype("image/png");
            });
    auto msgs = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await);
    REQUIRE(msgs.size() == 1);
    CHECK_FALSE(msgs[0].attachments[0].has_thumbnail);
    CHECK(error_code([&] { c->attachment_thumbnail(msgs[0].id, 0, await); }) == err::no_thumbnail);
}

TEST_CASE("Client: evicting a picture takes its thumbnail with it", "[client][thumbnail][evict]") {
    ScopedClockOffset clock{0s};
    Fixture f;
    auto [first, first_url] = f.arrive(picture(400, 300));
    REQUIRE(f.attachment(first).has_thumbnail);
    REQUIRE(std::filesystem::exists(f.thumb_file(first_url)));

    // Room for one entry, so the next arrival pushes the first out.
    AdjustedClock::set_offset(1s);
    f.c->set_attachment_cache_limit(1, await);
    f.rec.msg_updated.clear();
    auto [second, second_url] = f.arrive(picture(300, 400));

    CHECK_FALSE(std::filesystem::exists(f.file(first_url)));
    CHECK_FALSE(std::filesystem::exists(f.thumb_file(first_url)));
    auto a = f.attachment(first);
    CHECK(a.availability == AttachmentAvailability::absent);
    CHECK_FALSE(a.has_thumbnail);
    CHECK(error_code([&] { f.c->attachment_thumbnail(first, 0, await); }) == err::no_thumbnail);

    // And the message was told.
    bool reported = false;
    for (const auto& m : Recorder::messages(f.rec.msg_updated))
        if (m.id == first && !m.attachments[0].has_thumbnail)
            reported = true;
    CHECK(reported);

    // The one that did the pushing keeps both of its files.
    CHECK(f.attachment(second).has_thumbnail);
    CHECK(std::filesystem::exists(f.thumb_file(second_url)));
    CHECK(f.db_get("SELECT count(*) FROM attachment_cache") == 1);
}

TEST_CASE("Client: a file we send gets a thumbnail", "[client][thumbnail][send]") {
    TempCacheDir cache;
    TempClient c;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(cache.path);
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_outgoing", 7);
    std::filesystem::create_directories(dir);
    auto path = dir / "picture.jpg";
    auto bytes = picture(640, 480, ".jpg");
    {
        std::ofstream out{path, std::ios::binary};
        out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }

    // A gallery, which is kept as it is sent.
    auto id = c->send_message(
            ConversationId::dm(me),
            {.attachments = {OutgoingAttachment{.path = path, .content_type = "image/jpeg"}}},
            await);
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);
    settle(*c);

    auto a = c->message(id, await)->attachments.at(0);
    CHECK(a.availability == AttachmentAvailability::cached);
    CHECK(a.has_thumbnail);
    CHECK(jpeg_size(c->attachment_thumbnail(id, 0, await)) == std::pair{240, 240});

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: the thumbnail edge", "[client][thumbnail][edge]") {
    SECTION("defaults to 240") {
        TempClient c;
        CHECK(c->thumbnail_edge(await) == DEFAULT_THUMBNAIL_EDGE);
        CHECK(DEFAULT_THUMBNAIL_EDGE == 240);
    }

    SECTION("a stored value wins over the constructor's, at every open") {
        TempClient c{default_thumbnail_edge{100}};
        CHECK(c->thumbnail_edge(await) == 100);
        c->set_thumbnail_edge(300, await);
        CHECK(c->thumbnail_edge(await) == 300);

        c.reopen(default_thumbnail_edge{100});
        CHECK(c->thumbnail_edge(await) == 300);

        // Cleared, it goes back to what this run was constructed with.
        c->set_thumbnail_edge(std::nullopt, await);
        CHECK(c->thumbnail_edge(await) == 100);
    }

    SECTION("is clamped") {
        TempClient c{default_thumbnail_edge{2}};
        CHECK(c->thumbnail_edge(await) == image::min_thumbnail_edge);
        c->set_thumbnail_edge(5000, await);
        CHECK(c->thumbnail_edge(await) == image::max_thumbnail_edge);
        c->set_thumbnail_edge(10, await);
        CHECK(c->thumbnail_edge(await) == image::min_thumbnail_edge);
    }

    SECTION("a change applies to new thumbnails, and leaves the old ones") {
        Fixture f{default_thumbnail_edge{64}};
        auto [before, before_url] = f.arrive(picture(400, 300));
        CHECK(jpeg_size(f.c->attachment_thumbnail(before, 0, await)) == std::pair{64, 64});

        f.c->set_thumbnail_edge(128, await);
        auto [after, after_url] = f.arrive(picture(300, 400));
        CHECK(jpeg_size(f.c->attachment_thumbnail(after, 0, await)) == std::pair{128, 128});
        CHECK(jpeg_size(f.c->attachment_thumbnail(before, 0, await)) == std::pair{64, 64});
    }
}

TEST_CASE("Client: the startup pass fills in what was cached before", "[client][thumbnail]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    REQUIRE(f.attachment(id).has_thumbnail);
    auto size = f.c->attachment_cache_size(await);

    // At every open, not once: the second is the same state reached later.
    for (int open = 0; open < 2; open++) {
        INFO("open " << open);
        f.strip_thumbnail(url);
        REQUIRE_FALSE(f.attachment(id).has_thumbnail);

        f.reopen();
        CHECK(f.attachment(id).has_thumbnail);
        CHECK(std::filesystem::exists(f.thumb_file(url)));
        CHECK(f.c->attachment_cache_size(await) == size);
    }
}

TEST_CASE(
        "Client: a thumbnail still queued when the Client goes is made at the next open",
        "[client][thumbnail]") {
    Fixture f;
    TestHelper::stall_thumbnails(*f.c);
    auto [id, url] = f.arrive(picture(400, 300), "image/png", false);
    REQUIRE(TestHelper::thumbnails_queued(*f.c) == 1);
    REQUIRE_FALSE(f.attachment(id).has_thumbnail);

    f.reopen();
    CHECK(f.attachment(id).has_thumbnail);
    CHECK(jpeg_size(f.c->attachment_thumbnail(id, 0, await)) == std::pair{240, 240});
}

TEST_CASE(
        "Client: a picture no thumbnail could be made of is not tried at every open",
        "[client][thumbnail]") {
    Fixture f;
    std::vector<std::byte> junk(3000);
    random::fill(junk);
    auto [bad, bad_url] = f.arrive(junk, "image/png");
    REQUIRE_FALSE(f.attachment(bad).has_thumbnail);

    auto [good, good_url] = f.arrive(picture(400, 300));
    REQUIRE(f.attachment(good).has_thumbnail);

    // The failed entry's file becomes a picture, so that trying it again would be seen to succeed;
    // and the good one loses its thumbnail, so that the pass is seen to have run.
    std::filesystem::copy_file(
            f.file(good_url), f.file(bad_url), std::filesystem::copy_options::overwrite_existing);
    f.strip_thumbnail(good_url);

    f.reopen();
    CHECK(f.attachment(good).has_thumbnail);
    CHECK_FALSE(f.attachment(bad).has_thumbnail);
    CHECK_FALSE(std::filesystem::exists(f.thumb_file(bad_url)));

    // Nor when it is asked for.
    CHECK(error_code([&] { f.c->attachment_thumbnail(bad, 0, await); }) == err::no_thumbnail);
    CHECK(TestHelper::thumbnails_queued(*f.c) == 0);

    // Failed under an older thumbnailer, which is what raising the version makes of it.
    TestHelper::on_loop(f.c->core, [&] {
        f.c->core.database().conn().prepared_exec(
                "UPDATE attachment_derived SET failed = failed - 1 WHERE failed IS NOT NULL");
    });
    f.reopen();
    CHECK(f.attachment(bad).has_thumbnail);
    CHECK(f.db_get("SELECT count(*) FROM attachment_derived WHERE failed IS NOT NULL") == 0);
}

TEST_CASE("Client: the sweep reconciles thumbnails", "[client][thumbnail][evict]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    REQUIRE(f.attachment(id).has_thumbnail);
    auto size = f.c->attachment_cache_size(await);

    // A thumbnail whose entry has none: what a crash between writing and recording one leaves.
    auto stray = f.file("http://fs.example/file/ghost");
    stray += cache::THUMBNAIL_SUFFIX;
    std::ofstream{stray, std::ios::binary} << "no entry claims this";

    // And one gone from under its entry, which is taken out of the entry and made again: the file
    // it was made from is still good.
    std::filesystem::remove(f.thumb_file(url));
    f.rec.msg_updated.clear();

    f.c->set_cache_dir(f.dir.path);
    REQUIRE(eventually([&] { return std::filesystem::exists(f.thumb_file(url)); }));
    settle(*f.c);
    CHECK_FALSE(std::filesystem::exists(stray));
    CHECK(f.attachment(id).has_thumbnail);
    CHECK(f.c->attachment_cache_size(await) == size);

    // Reported as gone, and then as back.
    std::vector<bool> told;
    for (const auto& m : Recorder::messages(f.rec.msg_updated))
        if (m.id == id)
            told.push_back(m.attachments[0].has_thumbnail);
    CHECK(told == std::vector{false, true});
}

TEST_CASE("Client: a thumbnail found missing is made again", "[client][thumbnail]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    REQUIRE(f.attachment(id).has_thumbnail);
    std::filesystem::remove(f.thumb_file(url));

    CHECK(error_code([&] { f.c->attachment_thumbnail(id, 0, await); }) == err::no_thumbnail);
    settle(*f.c);
    CHECK(f.attachment(id).has_thumbnail);
    CHECK(jpeg_size(f.c->attachment_thumbnail(id, 0, await)) == std::pair{240, 240});
}

TEST_CASE("Client: a thumbnail is marked as attempted until it is made", "[client][thumbnail]") {
    // So that a decode that takes the process down with it is not tried again at every start.
    Fixture f;
    Hold hold{TestHelper::hold_thumbnail_thread(*f.c)};
    auto [id, url] = f.arrive(picture(400, 300), "image/png", false);
    CHECK(f.refused_under(url) == -image::thumbnailer_version);

    hold.release();
    settle(*f.c);
    CHECK(f.attachment(id).has_thumbnail);
    CHECK(f.refused_under(url) == 0);
}

TEST_CASE(
        "Client: closing while a thumbnail is being made leaves it to be made at the next open",
        "[client][thumbnail]") {
    Fixture f;
    TestHelper::stall_thumbnails(*f.c);
    auto [id, url] = f.arrive(picture(400, 300), "image/png", false);

    // The row marked and the decode's answer never delivered: what closing mid-decode leaves.
    auto entry = f.entry(url);
    TestHelper::on_loop(f.c->core, [&] {
        f.c->core.database().conn().prepared_exec(
                "INSERT INTO attachment_derived (entry, kind, failed) VALUES (?2, 1, ?1)",
                -image::thumbnailer_version,
                entry);
    });
    TestHelper::pretend_thumbnail_attempt(*f.c, entry);

    f.reopen();
    CHECK(f.attachment(id).has_thumbnail);
    CHECK(f.refused_under(url) == 0);
}

TEST_CASE(
        "Client: a decode that ended the process is tried once more, and then refused",
        "[client][thumbnail]") {
    Fixture f;
    Hold first{TestHelper::hold_thumbnail_thread(*f.c)};
    auto [a, a_url] = f.arrive(picture(400, 300), "image/png", false);
    auto [b, b_url] = f.arrive(picture(300, 400), "image/png", false);
    Hold second{TestHelper::hold_thumbnail_thread(*f.c)};

    // `b` as an earlier run left it, killed while decoding it.
    auto entry = f.entry(b_url);
    TestHelper::on_loop(f.c->core, [&] {
        f.c->core.database().conn().prepared_exec(
                "INSERT INTO attachment_derived (entry, kind, failed) VALUES (?2, 1, ?1)",
                -image::thumbnailer_version,
                entry);
    });
    first.release();
    REQUIRE(eventually([&] { return f.refused_under(b_url) == image::thumbnailer_version; }));

    // Settled as any other attempt is, should this one finish.
    second.release();
    settle(*f.c);
    CHECK(f.attachment(a).has_thumbnail);
    CHECK(f.attachment(b).has_thumbnail);
    CHECK(f.refused_under(b_url) == 0);
}

TEST_CASE(
        "Client: a thumbnail left by an attempt that did not settle is queued after the rest",
        "[client][thumbnail]") {
    // So that a picture whose decode ends the process does not do so before the backlog is made.
    Fixture f;
    auto [a, a_url] = f.arrive(picture(400, 300));
    auto [b, b_url] = f.arrive(picture(300, 400));
    f.strip_thumbnail(a_url);
    f.strip_thumbnail(b_url);
    auto ea = f.entry(a_url), eb = f.entry(b_url);
    TestHelper::on_loop(f.c->core, [&] {
        auto conn = f.c->core.database().conn();
        conn.prepared_exec("UPDATE attachment_cache SET last_used = 1000 WHERE id = ?", ea);
        conn.prepared_exec("UPDATE attachment_cache SET last_used = 2000 WHERE id = ?", eb);
        conn.prepared_exec(
                "INSERT INTO attachment_derived (entry, kind, failed) VALUES (?2, 1, ?1)",
                -image::thumbnailer_version,
                eb);
    });

    TestHelper::stall_thumbnails(*f.c);
    TestHelper::thumbnail_pass(*f.c);
    CHECK(TestHelper::thumbnails_pending(*f.c) == std::vector{ea, eb});
}

TEST_CASE(
        "Client: a thumbnail that fails to be made is tried again at the next open",
        "[client][thumbnail]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    auto good = contents(f.file(url));
    f.strip_thumbnail(url);

    // Not an encrypted file at all, so making a thumbnail throws rather than refusing.
    std::vector<std::byte> junk(3000);
    random::fill(junk);
    overwrite(f.file(url), junk);
    f.reopen();
    CHECK_FALSE(f.attachment(id).has_thumbnail);
    CHECK(f.refused_under(url) == 0);

    // Not at every ask meanwhile, which would decode it again each time a tile is bound.
    {
        Hold hold{TestHelper::hold_thumbnail_thread(*f.c)};
        CHECK(error_code([&] { f.c->attachment_thumbnail(id, 0, await); }) == err::no_thumbnail);
        CHECK(f.refused_under(url) == 0);
        CHECK(TestHelper::thumbnails_queued(*f.c) == 0);
    }

    overwrite(f.file(url), good);
    f.reopen();
    CHECK(f.attachment(id).has_thumbnail);
}

TEST_CASE("Client: a thumbnail asked for before it is made is made next", "[client][thumbnail]") {
    Fixture f;
    Hold hold{TestHelper::hold_thumbnail_thread(*f.c)};
    std::vector<std::pair<int64_t, std::string>> arrived;
    for (auto [w, h] : {std::pair{400, 300}, std::pair{300, 400}, std::pair{200, 300}})
        arrived.push_back(f.arrive(picture(w, h), "image/png", false));
    auto [first, first_url] = arrived[0];
    auto [last, last_url] = arrived[2];

    // The first is being made; the others wait in the order they came.
    REQUIRE(TestHelper::thumbnails_pending(*f.c) ==
            std::vector{f.entry(arrived[1].second), f.entry(last_url)});

    // Asked for twice, as a tile bound again would: moved, not queued again.
    for (int i = 0; i < 2; i++)
        CHECK(error_code([&] { f.c->attachment_thumbnail(last, 0, await); }) == err::no_thumbnail);
    CHECK(TestHelper::thumbnails_pending(*f.c) ==
          std::vector{f.entry(last_url), f.entry(arrived[1].second)});

    hold.release();
    settle(*f.c);
    for (const auto& [id, url] : arrived)
        CHECK(f.attachment(id).has_thumbnail);
}

TEST_CASE("Client: a picture we send carries its own placeholder", "[client][send][placeholder]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_placeholder", 7);
    std::filesystem::create_directories(dir);
    auto write = [&](std::string_view name, std::span<const std::byte> bytes) {
        auto p = dir / name;
        std::ofstream out{p, std::ios::binary};
        out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        return p;
    };
    auto photo = write("photo.jpg", picture(640, 480, ".jpg"));
    auto doc = write("notes.pdf", std::vector<std::byte>(300, std::byte{1}));
    auto junk = write("junk.png", std::vector<std::byte>(300, std::byte{2}));
    auto supplied = std::vector<std::byte>(5, std::byte{9});

    auto id = c->send_message(
            ConversationId::dm(me),
            {.attachments =
                     {OutgoingAttachment{.path = photo},
                      OutgoingAttachment{.path = doc},
                      OutgoingAttachment{.path = junk, .content_type = "image/png"},
                      OutgoingAttachment{
                              .path = photo,
                              .original_file = true,
                              .width = 4,
                              .height = 3,
                              .thumbhash = supplied}}},
            await);
    REQUIRE(eventually([&] {
        sync(*c);
        return accept_stores(*net) == 1;
    }));
    sync(*c);

    auto msg = c->message(id, await);
    REQUIRE(msg);
    REQUIRE(msg->attachments.size() == 4);

    // Read from the file, and sent: the row is what the content was built from.
    const auto& a = msg->attachments[0];
    CHECK(a.width == 640);
    CHECK(a.height == 480);
    REQUIRE(a.thumbhash);
    CHECK(image::thumbhash::valid(*a.thumbhash));
    CHECK(a.uploaded);

    // Not a picture: nothing is read.  A picture that cannot be decoded is sent without.
    CHECK_FALSE(msg->attachments[1].width);
    CHECK_FALSE(msg->attachments[1].thumbhash);
    CHECK_FALSE(msg->attachments[2].width);
    CHECK_FALSE(msg->attachments[2].thumbhash);
    CHECK(msg->attachments[2].uploaded);

    // What the caller supplied for a file sent as it is stays theirs.
    CHECK(msg->attachments[3].width == 4);
    CHECK(msg->attachments[3].height == 3);
    CHECK(msg->attachments[3].thumbhash == supplied);

    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: a retried send reads what a picture still lacks", "[client][send][placeholder]") {
    TempClient c;
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);
    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_placeholder", 7);
    std::filesystem::create_directories(dir);
    auto photo = dir / "photo.jpg";
    {
        auto bytes = picture(640, 480, ".jpg");
        std::ofstream out{photo, std::ios::binary};
        out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }

    // No network: the upload fails, and the message waits to be retried.
    auto id = c->send_message(
            ConversationId::dm(me), {.attachments = {OutgoingAttachment{.path = photo}}}, await);
    sync(*c);
    REQUIRE(c->message(id, await)->send_state == SendState::failed);

    // As a row left by a run that ended before the derive stage.
    TestHelper::on_loop(c->core, [&] {
        c->core.database().conn().prepared_exec(
                "UPDATE message_attachments SET width = NULL, height = NULL, thumbhash = NULL"
                " WHERE message = ?",
                id);
    });
    REQUIRE_FALSE(c->message(id, await)->attachments.at(0).thumbhash);

    auto* net = attach_mock_network(c->core);
    REQUIRE(c->retry_send(id, nullptr, await));
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);
    sync(*c);
    auto a = c->message(id, await)->attachments.at(0);
    CHECK(a.width == 640);
    CHECK(a.height == 480);
    REQUIRE(a.thumbhash);
    CHECK(image::thumbhash::valid(*a.thumbhash));
    CHECK(a.uploaded);

    std::filesystem::remove_all(dir);
}
