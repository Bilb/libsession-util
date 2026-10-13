#include "common.hpp"

namespace {

using files = std::vector<std::string>;

// One conversation with a peer, whose files a mock network serves, and a way to restart.
struct Backlog {
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    ConversationId convo = ConversationId::dm(peer.session_id);
    // Onion requests fetch one file at a time, which is what makes an order observable.
    bool one_at_a_time;
    MockNetwork* net = nullptr;
    std::map<std::string, std::vector<std::byte>> served;
    decltype(random::random(32)) seed = random::random(32);
    int64_t when = 1000;

    explicit Backlog(bool one_at_a_time = false) : one_at_a_time{one_at_a_time} {
        attach();
        c->set_cache_dir(dir.path);
        c->open_dm(convo, await);
    }

    void attach() {
        network::config::Config config;
        if (!one_at_a_time)
            config.router = network::opt::router::Type::direct;
        net = attach_mock_network(c->core, std::move(config));
        net->served = served;
        sync(*c);
    }

    // A restart, with the cache directory and the network given back in either order.
    void reopen(bool network_first) {
        c.reopen();
        if (network_first)
            attach();
        c->set_cache_dir(dir.path);
        sync(*c);
        if (!network_first)
            attach();
        sync(*c);
    }

    // A message carrying one file, served as `file`.  Returns the message's id.
    int64_t arrive(const std::string& file, std::string type = "image/png", size_t size = 3000) {
        std::vector<std::byte> data(size);
        random::fill(data);
        auto [ct, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
        served[file] = ct;
        net->served[file] = ct;
        deliver(*c,
                peer,
                "",
                from_epoch_ms(when++),
                "h" + file,
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(1);
                    a->set_url(network::file_server::generate_download_url(file, {}, true));
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(size);
                    a->set_contenttype(type);
                });
        sync(*c);
        return c->conversation(convo, await)->messages(await)[0].id;
    }

    void set(AutoDownload mode, ExistingAttachments existing) {
        c->conversation(convo, await)->set_auto_download(mode, existing, await);
        sync(*c);
    }

    ExistingAttachmentCounts counts() {
        return c->conversation(convo, await)->existing_attachments(await);
    }

    // The files being fetched, in the order they were asked for.
    files fetching() const {
        files found;
        for (const auto& r : net->downloads)
            found.push_back(network::file_server::parse_download_url(r.download_url)->file_id);
        return found;
    }

    void serve() {
        serve_downloads(*net);
        sync(*c);
    }

    void request(int64_t message) {
        c->attachment_data(message, 0, nullptr, [](auto) {});
        sync(*c);
    }
};

}  // namespace

TEST_CASE(
        "Client: turning auto-download on can fetch what is already here",
        "[client][auto][existing]") {
    Backlog b;
    auto image = b.arrive("a");
    auto doc = b.arrive("b", "application/pdf");
    b.arrive("c", "image/png", 20000);
    REQUIRE(b.fetching().empty());

    SECTION("leaving it fetches only what arrives afterwards") {
        b.set(AutoDownload::all, ExistingAttachments::leave);
        CHECK(b.fetching().empty());
        b.arrive("d");
        CHECK(b.fetching() == files{"d"});
    }

    SECTION("the count is what fetching then queues, for either mode") {
        auto n = b.counts();
        CHECK(n.all.count == 3);
        CHECK(n.all.bytes == 26000);
        CHECK(n.image_attachments.count == 2);
        CHECK(n.image_attachments.bytes == 23000);

        b.c->set_auto_download_max_size(10000, await);
        n = b.counts();
        CHECK(n.all.count == 2);
        CHECK(n.all.bytes == 6000);
        CHECK(n.image_attachments.count == 1);

        b.set(AutoDownload::all, ExistingAttachments::fetch);
        CHECK(b.fetching() == files{"b", "a"});
        CHECK(b.counts().all.count == 0);
    }

    SECTION("images only fetches the pictures, newest first") {
        b.set(AutoDownload::image_attachments, ExistingAttachments::fetch);
        CHECK(b.fetching() == files{"c", "a"});
    }

    SECTION("asking with the mode unchanged still fetches") {
        b.set(AutoDownload::all, ExistingAttachments::leave);
        b.set(AutoDownload::all, ExistingAttachments::fetch);
        CHECK(b.fetching() == files{"c", "b", "a"});
    }

    SECTION("there is nothing to fetch with it off") {
        CHECK_THROWS_AS(
                b.set(AutoDownload::none, ExistingAttachments::fetch), std::invalid_argument);
        CHECK_FALSE(b.c->conversation(b.convo, await)->auto_download().has_value());
    }

    SECTION("a file already here is neither counted nor fetched") {
        b.request(image);
        b.serve();
        CHECK(b.counts().all.count == 2);
        b.set(AutoDownload::all, ExistingAttachments::fetch);
        CHECK(b.fetching() == files{"c", "b"});
    }

    SECTION("a file the server no longer has is neither counted nor fetched") {
        b.request(doc);
        fail_downloads(*b.net, 404);
        sync(*b.c);
        CHECK(b.counts().all.count == 2);
        b.set(AutoDownload::all, ExistingAttachments::fetch);
        CHECK(b.fetching() == files{"c", "a"});
    }
}

TEST_CASE("Client: a new arrival goes ahead of the backlog", "[client][auto][existing]") {
    Backlog b{true};
    b.arrive("a");
    b.arrive("b");
    b.set(AutoDownload::all, ExistingAttachments::fetch);
    REQUIRE(b.fetching() == files{"b"});

    b.arrive("c");
    b.serve();
    CHECK(b.fetching() == files{"c"});
    b.serve();
    CHECK(b.fetching() == files{"a"});
}

TEST_CASE("Client: what auto-download still owes survives a restart", "[client][auto][existing]") {
    bool network_first = GENERATE(false, true);
    Backlog b{true};
    b.arrive("a");
    b.arrive("b");
    b.set(AutoDownload::all, ExistingAttachments::fetch);
    REQUIRE(b.fetching() == files{"b"});

    b.reopen(network_first);
    CHECK(b.fetching() == files{"b"});
    b.serve();
    CHECK(b.fetching() == files{"a"});
    b.serve();
    CHECK(b.fetching().empty());

    b.reopen(network_first);
    CHECK(b.fetching().empty());
}

TEST_CASE("Client: an evicted file is not owed again", "[client][auto][existing][evict]") {
    Backlog b;
    b.arrive("a");
    b.arrive("b");
    // Room for one of the two, so the second to land evicts the first.
    b.c->set_attachment_cache_limit(4000, await);
    b.set(AutoDownload::all, ExistingAttachments::fetch);
    REQUIRE(b.fetching() == files{"b", "a"});
    b.serve();

    size_t cached = 0;
    for (const auto& m : b.c->conversation(b.convo, await)->messages(await))
        cached += m.attachments[0].availability == AttachmentAvailability::cached;
    REQUIRE(cached == 1);

    b.reopen(false);
    CHECK(b.fetching().empty());
}

TEST_CASE(
        "Client: changing the setting forgets what it no longer takes",
        "[client][auto][existing]") {
    Backlog b{true};
    b.arrive("a");
    b.arrive("b", "application/pdf");
    b.arrive("c");
    b.set(AutoDownload::all, ExistingAttachments::fetch);
    REQUIRE(b.fetching() == files{"c"});

    SECTION("off forgets all of it, and on again does not bring it back") {
        b.set(AutoDownload::none, ExistingAttachments::leave);
        b.serve();
        CHECK(b.fetching().empty());

        b.reopen(false);
        CHECK(b.fetching().empty());
        b.set(AutoDownload::all, ExistingAttachments::leave);
        CHECK(b.fetching().empty());
    }

    SECTION("images only forgets the rest") {
        b.set(AutoDownload::image_attachments, ExistingAttachments::leave);
        b.serve();
        CHECK(b.fetching() == files{"a"});
        b.serve();
        CHECK(b.fetching().empty());
    }
}

TEST_CASE(
        "Client: a failed auto-download stays owed only while it may succeed",
        "[client][auto][existing]") {
    Backlog b{true};
    b.arrive("a");
    b.set(AutoDownload::all, ExistingAttachments::fetch);
    REQUIRE(b.fetching() == files{"a"});

    SECTION("a file the server no longer has is dropped") {
        fail_downloads(*b.net, 404);
        sync(*b.c);
        b.reopen(false);
        CHECK(b.fetching().empty());
    }

    SECTION("a transient failure is tried again at the next start, not before") {
        fail_downloads(*b.net, 503);
        sync(*b.c);
        CHECK(b.fetching().empty());
        b.reopen(false);
        CHECK(b.fetching() == files{"a"});
    }
}

TEST_CASE("Client: a file fetched another way is no longer owed", "[client][auto][existing]") {
    Backlog b{true};
    auto older = b.arrive("a");
    b.arrive("b");
    b.set(AutoDownload::all, ExistingAttachments::fetch);
    REQUIRE(b.fetching() == files{"b"});

    // Asked for directly while it waits its turn, and held to no auto-download limit.
    b.request(older);
    REQUIRE(b.fetching() == files{"b", "a"});
    b.serve();
    CHECK(b.fetching().empty());

    b.reopen(false);
    CHECK(b.fetching().empty());
}
