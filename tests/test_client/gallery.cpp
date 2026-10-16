#include <session/client/error_codes.hpp>

#include "../utils.hpp"
#include "common.hpp"

namespace {

// Delivers a message carrying one attachment per content type, and returns its id.
int64_t arrive(
        Client& c,
        const SenderKeys& from,
        const ConversationId& convo,
        std::string hash,
        const std::vector<std::string>& content_types,
        std::optional<b33> sync_target = std::nullopt) {
    deliver(c,
            from,
            "",
            from_epoch_ms(1000),
            std::move(hash),
            "",
            sync_target,
            [&](SessionProtos::DataMessage& d) {
                int i = 0;
                for (const auto& ct : content_types) {
                    auto* a = d.add_attachments();
                    a->set_id(++i);
                    a->set_url(network::file_server::generate_download_url(
                            fmt::format("f{}", i), {}, true));
                    a->set_size(100);
                    a->set_contenttype(ct);
                }
            });
    sync(c);
    return c.conversation(convo, await)->messages(await)[0].id;
}

}  // namespace

TEST_CASE("Client: a message that can be a gallery starts as one", "[client][gallery]") {
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);
    auto convo = ConversationId::dm(peer.session_id);
    c->open_dm(convo, await);

    auto check = [&](std::string hash) {
        auto pictures = arrive(*c, peer, convo, hash + "p", {"image/jpeg", "IMAGE/PNG"});
        auto m = c->message(pictures, await);
        REQUIRE(m);
        CHECK(m->gallery_viewable);
        CHECK(m->gallery);

        auto labelled = arrive(
                *c, peer, convo, hash + "l", {"image/jpeg; charset=binary", "IMAGE/PNG ; foo=bar"});
        m = c->message(labelled, await);
        REQUIRE(m);
        CHECK(m->gallery_viewable);
        CHECK(m->gallery);

        auto mixed = arrive(*c, peer, convo, hash + "m", {"image/jpeg", "application/pdf"});
        m = c->message(mixed, await);
        REQUIRE(m);
        CHECK_FALSE(m->gallery_viewable);
        CHECK_FALSE(m->gallery);

        for (auto [suffix, type] :
             {std::pair{"d", "application/pdf"},
              std::pair{"s", "image/svg+xml"},
              std::pair{"j", "image/jpeg2000"},
              std::pair{"a", "image/apng"}}) {
            auto one = arrive(*c, peer, convo, hash + suffix, {type});
            m = c->message(one, await);
            REQUIRE(m);
            CHECK_FALSE(m->gallery_viewable);
            CHECK_FALSE(m->gallery);
        }
    };

    SECTION("with auto-download never asked") {
        check("h");
        CHECK(net->downloads.empty());
    }
    SECTION("with auto-download off") {
        c->conversation(convo, await)->set_auto_download(AutoDownload::none, await);
        check("h");
        CHECK(net->downloads.empty());
    }
    SECTION("with auto-download on") {
        c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);
        check("h");
        CHECK_FALSE(net->downloads.empty());
    }
}

TEST_CASE(
        "Client: a message of ours synced from another device starts as a gallery",
        "[client][gallery]") {
    TempClient c;
    SenderKeys peer;
    attach_mock_network(c->core);
    auto convo = ConversationId::dm(peer.session_id);
    c->open_dm(convo, await);

    auto id = arrive(*c, self_keys(*c), convo, "s1", {"image/jpeg", "image/webp"}, peer.session_id);
    auto m = c->message(id, await);
    REQUIRE(m);
    CHECK(m->outgoing);
    CHECK(m->gallery_viewable);
    CHECK(m->gallery);
}

TEST_CASE("Client: a message we send starts as a gallery", "[client][gallery]") {
    TempClient c;
    attach_mock_network(c->core);
    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_gallery", 7);
    std::filesystem::create_directories(dir);
    auto write = [&](std::string_view name) {
        auto p = dir / name;
        std::ofstream{p, std::ios::binary} << "not really a picture";
        return p;
    };
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto pictures = c->send_message(
            ConversationId::dm(me),
            {.attachments =
                     {OutgoingAttachment{.path = write("a.jpg")},
                      OutgoingAttachment{.path = write("b.png")}}},
            await);
    auto m = c->message(pictures, await);
    REQUIRE(m);
    CHECK(m->gallery_viewable);
    CHECK(m->gallery);

    auto mixed = c->send_message(
            ConversationId::dm(me),
            {.attachments =
                     {OutgoingAttachment{.path = write("c.jpg")},
                      OutgoingAttachment{.path = write("notes.pdf")}}},
            await);
    m = c->message(mixed, await);
    REQUIRE(m);
    CHECK_FALSE(m->gallery_viewable);
    CHECK_FALSE(m->gallery);

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: set_gallery is the reader's word, and starts nothing", "[client][gallery]") {
    Recorder r;
    TempClient c{r.handlers()};
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    auto convo = ConversationId::dm(peer.session_id);
    c->open_dm(convo, await);

    auto pictures = arrive(*c, peer, convo, "p", {"image/jpeg", "image/png"});
    auto mixed = arrive(*c, peer, convo, "m", {"image/jpeg", "application/pdf"});
    auto updates_for = [&](int64_t id) {
        int n = 0;
        for (const auto& m : Recorder::messages(r.msg_updated))
            if (m.id == id)
                ++n;
        return n;
    };

    // Off, which is always allowed, reported once; asking again changes nothing and says nothing.
    r.msg_updated.clear();
    CHECK(c->set_gallery(pictures, false, await));
    sync(*c);
    CHECK_FALSE(c->message(pictures, await)->gallery);
    CHECK(updates_for(pictures) == 1);
    CHECK(c->set_gallery(pictures, false, await));
    sync(*c);
    CHECK(updates_for(pictures) == 1);

    // Back on: reported once, and nothing is fetched for it.
    CHECK(c->set_gallery(pictures, true, await));
    sync(*c);
    CHECK(c->message(pictures, await)->gallery);
    CHECK(updates_for(pictures) == 2);
    CHECK(net->downloads.empty());

    // A message that cannot be shown as a gallery is refused, silently.
    r.msg_updated.clear();
    CHECK_FALSE(c->set_gallery(mixed, true, await));
    sync(*c);
    CHECK_FALSE(c->message(mixed, await)->gallery);
    CHECK(updates_for(mixed) == 0);
    CHECK_FALSE(c->set_gallery(mixed + 1000, true, await));
}
