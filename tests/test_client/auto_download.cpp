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

    explicit Backlog(bool one_at_a_time = false, bool with_cache = true) :
            one_at_a_time{one_at_a_time} {
        attach();
        if (with_cache)
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

    struct File {
        std::vector<std::byte> ciphertext, key;
        std::string type;
        size_t size;
    };
    std::map<std::string, File> made;

    // A message carrying one new file, served as `file`, sent at `ts` (else just after the last).
    // Returns the message's id.
    int64_t arrive(
            const std::string& file,
            std::string type = "image/png",
            size_t size = 3000,
            std::optional<int64_t> ts = std::nullopt) {
        std::vector<std::byte> data(size);
        random::fill(data);
        auto [ct, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
        made[file] = {ct, to_vector<std::byte>(key), std::move(type), size};
        served[file] = ct;
        net->served[file] = ct;
        return carry(file, "h" + file, ts);
    }

    // Another message carrying the same pointer as one `arrive` made, as a forward or a quote of
    // it does: one file, two rows.
    int64_t carry(
            const std::string& file, std::string hash, std::optional<int64_t> ts = std::nullopt) {
        const auto& f = made.at(file);
        deliver(*c,
                peer,
                "",
                from_epoch_ms(ts ? *ts : when++),
                std::move(hash),
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(1);
                    a->set_url(network::file_server::generate_download_url(file, {}, true));
                    a->set_key(
                            std::string{reinterpret_cast<const char*>(f.key.data()), f.key.size()});
                    a->set_size(f.size);
                    a->set_contenttype(f.type);
                });
        sync(*c);
        // Ids only grow, so the newest arrival is the largest whatever its timestamp.
        int64_t newest = 0;
        for (const auto& m : c->conversation(convo, await)->messages(await))
            newest = std::max(newest, m.id);
        return newest;
    }

    void set(AutoDownload mode) {
        c->conversation(convo, await)->set_auto_download(mode, await);
        sync(*c);
    }

    // `mode`, and what is already here too: what a ticked "also download what is here" does.
    void fetch(AutoDownload mode) {
        set(mode);
        fetch_existing();
    }

    void fetch_existing() {
        c->conversation(convo, await)->download_existing_attachments(await);
        sync(*c);
    }

    // Rows still flagged, which the unavailable paths leave no other way to observe.
    int64_t owed() {
        return c->core.loop().call_get([&] {
            return c->core.database().conn().prepared_get<int64_t>(
                    "SELECT count(*) FROM message_attachments WHERE auto_pending IS NOT NULL");
        });
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
    Backlog chat;
    auto image = chat.arrive("a");
    auto doc = chat.arrive("b", "application/pdf");
    chat.arrive("c", "image/png", 20000);
    REQUIRE(chat.fetching().empty());

    SECTION("leaving it fetches only what arrives afterwards") {
        chat.set(AutoDownload::all);
        CHECK(chat.fetching().empty());
        chat.arrive("d");
        CHECK(chat.fetching() == files{"d"});
    }

    SECTION("the count is what fetching then queues, for either mode") {
        auto n = chat.counts();
        CHECK(n.all.count == 3);
        CHECK(n.all.bytes == 26000);
        CHECK(n.image_attachments.count == 2);
        CHECK(n.image_attachments.bytes == 23000);

        chat.c->set_auto_download_max_size(10000, await);
        n = chat.counts();
        CHECK(n.all.count == 2);
        CHECK(n.all.bytes == 6000);
        CHECK(n.image_attachments.count == 1);

        chat.fetch(AutoDownload::all);
        CHECK(chat.fetching() == files{"b", "a"});
        // Still counted while only queued: they are not here yet.
        CHECK(chat.counts().all.count == 2);
        chat.serve();
        CHECK(chat.counts().all.count == 0);
    }

    SECTION("images only fetches the pictures, newest first") {
        chat.fetch(AutoDownload::image_attachments);
        CHECK(chat.fetching() == files{"c", "a"});
    }

    SECTION("asking later, with the setting already on, still fetches") {
        chat.set(AutoDownload::all);
        chat.fetch_existing();
        CHECK(chat.fetching() == files{"c", "b", "a"});
    }

    SECTION("there is nothing to fetch with it unset or off") {
        CHECK_THROWS_AS(chat.fetch_existing(), std::invalid_argument);
        chat.set(AutoDownload::none);
        CHECK_THROWS_AS(chat.fetch_existing(), std::invalid_argument);
        CHECK(chat.fetching().empty());
    }

    SECTION("a file already here is neither counted nor fetched") {
        chat.request(image);
        chat.serve();
        CHECK(chat.counts().all.count == 2);
        chat.fetch(AutoDownload::all);
        CHECK(chat.fetching() == files{"c", "b"});
    }

    SECTION("a file the server no longer has is neither counted nor fetched") {
        chat.request(doc);
        fail_downloads(*chat.net, 404);
        sync(*chat.c);
        CHECK(chat.counts().all.count == 2);
        chat.fetch(AutoDownload::all);
        CHECK(chat.fetching() == files{"c", "a"});
    }
}

TEST_CASE("Client: a new arrival goes ahead of the backlog", "[client][auto][existing]") {
    Backlog chat{true};
    chat.arrive("a");
    chat.arrive("b");
    chat.fetch(AutoDownload::all);
    REQUIRE(chat.fetching() == files{"b"});

    chat.arrive("c");
    chat.serve();
    CHECK(chat.fetching() == files{"c"});
    chat.serve();
    CHECK(chat.fetching() == files{"a"});
}

TEST_CASE("Client: what auto-download still owes survives a restart", "[client][auto][existing]") {
    bool network_first = GENERATE(false, true);
    Backlog chat{true};
    chat.arrive("a");
    chat.arrive("b");
    chat.fetch(AutoDownload::all);
    REQUIRE(chat.fetching() == files{"b"});

    chat.reopen(network_first);
    CHECK(chat.fetching() == files{"b"});
    chat.serve();
    CHECK(chat.fetching() == files{"a"});
    chat.serve();
    CHECK(chat.fetching().empty());

    chat.reopen(network_first);
    CHECK(chat.fetching().empty());
}

TEST_CASE("Client: an evicted file is not owed again", "[client][auto][existing][evict]") {
    Backlog chat;
    chat.arrive("a");
    chat.arrive("b");
    // Room for one of the two, so the second to land evicts the first.
    chat.c->set_attachment_cache_limit(4000, await);
    chat.fetch(AutoDownload::all);
    REQUIRE(chat.fetching() == files{"b", "a"});
    chat.serve();

    size_t cached = 0;
    for (const auto& m : chat.c->conversation(chat.convo, await)->messages(await))
        cached += m.attachments[0].availability == AttachmentAvailability::cached;
    REQUIRE(cached == 1);

    chat.reopen(false);
    CHECK(chat.fetching().empty());
}

TEST_CASE(
        "Client: changing the setting forgets what it no longer takes",
        "[client][auto][existing]") {
    Backlog chat{true};
    chat.arrive("a");
    chat.arrive("b", "application/pdf");
    chat.arrive("c");
    chat.fetch(AutoDownload::all);
    REQUIRE(chat.fetching() == files{"c"});

    SECTION("off forgets all of it, and on again does not bring it back") {
        chat.set(AutoDownload::none);
        chat.serve();
        CHECK(chat.fetching().empty());

        chat.reopen(false);
        CHECK(chat.fetching().empty());
        chat.set(AutoDownload::all);
        CHECK(chat.fetching().empty());
    }

    SECTION("off then on again, with the rest still queued, does not bring it back") {
        chat.set(AutoDownload::none);
        chat.set(AutoDownload::all);
        chat.serve();
        CHECK(chat.fetching().empty());
    }

    SECTION("images only forgets the rest") {
        chat.set(AutoDownload::image_attachments);
        chat.serve();
        CHECK(chat.fetching() == files{"a"});
        chat.serve();
        CHECK(chat.fetching().empty());
    }
}

TEST_CASE(
        "Client: a failed auto-download stays owed only while it may succeed",
        "[client][auto][existing]") {
    Backlog chat{true};
    chat.arrive("a");
    chat.fetch(AutoDownload::all);
    REQUIRE(chat.fetching() == files{"a"});

    SECTION("a file the server no longer has is dropped") {
        fail_downloads(*chat.net, 404);
        sync(*chat.c);
        chat.reopen(false);
        CHECK(chat.fetching().empty());
    }

    SECTION("a transient failure is tried again at the next start, not before") {
        fail_downloads(*chat.net, 503);
        sync(*chat.c);
        CHECK(chat.fetching().empty());
        chat.reopen(false);
        CHECK(chat.fetching() == files{"a"});
    }

    SECTION("asking again retries what a failed attempt left owed") {
        fail_downloads(*chat.net, 503);
        sync(*chat.c);
        CHECK(chat.counts().all.count == 1);
        chat.fetch(AutoDownload::all);
        CHECK(chat.fetching() == files{"a"});
    }
}

TEST_CASE("Client: a file fetched another way is no longer owed", "[client][auto][existing]") {
    Backlog chat{true};
    auto older = chat.arrive("a");
    chat.arrive("b");
    chat.fetch(AutoDownload::all);
    REQUIRE(chat.fetching() == files{"b"});

    // Asked for directly while it waits its turn, and held to no auto-download limit.
    chat.request(older);
    REQUIRE(chat.fetching() == files{"b", "a"});
    chat.serve();
    CHECK(chat.fetching().empty());

    chat.reopen(false);
    CHECK(chat.fetching().empty());
}

TEST_CASE(
        "Client: a file several messages carry is counted and fetched once",
        "[client][auto][existing]") {
    Backlog chat;
    auto first = chat.arrive("a");
    auto forward = chat.carry("a", "h-forward");
    auto n = chat.counts();
    CHECK(n.all.count == 1);
    CHECK(n.all.bytes == 3000);

    chat.fetch(AutoDownload::all);
    CHECK(chat.fetching() == files{"a"});
    chat.serve();
    for (auto id : {first, forward})
        CHECK(chat.c->message(id, await)->attachments[0].availability ==
              AttachmentAvailability::cached);
}

TEST_CASE(
        "Client: the backlog goes newest message first by when it was sent",
        "[client][auto][existing]") {
    Backlog chat{true};
    chat.arrive("newer", "image/png", 3000, 5000);
    // Delivered after, sent before: a late or synced delivery.
    chat.arrive("older", "image/png", 3000, 2000);
    chat.fetch(AutoDownload::all);
    CHECK(chat.fetching() == files{"newer"});
}

TEST_CASE(
        "Client: a size limit lowered while queued forgets what it refuses",
        "[client][auto][existing]") {
    Backlog chat{true};
    chat.arrive("a");
    chat.arrive("b");
    chat.fetch(AutoDownload::all);
    REQUIRE(chat.fetching() == files{"b"});

    // Raised again before the queue reaches `a`: it was forgotten when the limit refused it.
    chat.c->set_auto_download_max_size(1000, await);
    chat.c->set_auto_download_max_size(std::nullopt, await);
    chat.serve();
    CHECK(chat.fetching().empty());
    chat.reopen(false);
    CHECK(chat.fetching().empty());
}

TEST_CASE("Client: a message deleted while queued is not fetched", "[client][auto][existing]") {
    Backlog chat{true};
    auto older = chat.arrive("a");
    chat.arrive("b");
    chat.fetch(AutoDownload::all);
    REQUIRE(chat.fetching() == files{"b"});

    chat.c->delete_message(older, await);
    chat.serve();
    CHECK(chat.fetching().empty());
    chat.reopen(false);
    CHECK(chat.fetching().empty());
}

TEST_CASE("Client: without a cache there is nothing to fetch", "[client][auto][existing]") {
    Backlog chat{false, false};
    chat.arrive("a");
    auto n = chat.counts();
    CHECK(n.all.count == 0);
    CHECK(n.image_attachments.count == 0);

    chat.fetch(AutoDownload::all);
    CHECK(chat.fetching().empty());
    chat.c->set_cache_dir(chat.dir.path);
    sync(*chat.c);
    CHECK(chat.fetching().empty());
}

TEST_CASE("Client: reloading the queue does not fetch a file twice", "[client][auto][existing]") {
    Backlog chat;
    chat.c->set_auto_download_concurrency(2, await);
    chat.arrive("a");
    chat.fetch(AutoDownload::all);
    REQUIRE(chat.fetching() == files{"a"});

    // A second reload while `a` runs must not spend the other slot joining it.
    chat.c->set_cache_dir(chat.dir.path);
    sync(*chat.c);
    chat.arrive("b");
    CHECK(chat.fetching() == files{"a", "b"});
}

TEST_CASE(
        "Client: a file several messages carry takes one slot, not one each",
        "[client][auto][existing]") {
    Backlog chat;
    chat.c->set_auto_download_concurrency(2, await);
    chat.arrive("x");
    chat.arrive("a");
    chat.carry("a", "h-forward");
    chat.fetch(AutoDownload::all);
    CHECK(chat.fetching() == files{"a", "x"});
}

TEST_CASE("Client: asking twice does not queue anything twice", "[client][auto][existing]") {
    Backlog chat{true};
    chat.arrive("a");
    chat.arrive("b");
    chat.arrive("c");
    chat.fetch(AutoDownload::all);
    chat.fetch_existing();
    REQUIRE(chat.fetching() == files{"c"});
    chat.serve();
    REQUIRE(chat.fetching() == files{"b"});
    chat.serve();
    REQUIRE(chat.fetching() == files{"a"});

    // A duplicate entry would try `a` again at once.
    fail_downloads(*chat.net, 503);
    sync(*chat.c);
    CHECK(chat.fetching().empty());
}

TEST_CASE("Client: a file found unavailable is no longer owed", "[client][auto][existing]") {
    Backlog chat{true};
    chat.fetch(AutoDownload::all);
    chat.arrive("a");
    REQUIRE(chat.fetching() == files{"a"});
    REQUIRE(chat.owed() == 1);

    SECTION("the server no longer has it") {
        fail_downloads(*chat.net, 404);
        sync(*chat.c);
        CHECK(chat.owed() == 0);
    }

    SECTION("its bytes are not the file they claimed to be") {
        std::vector<std::byte> garbage(4000);
        random::fill(garbage);
        serve_downloads(*chat.net, garbage);
        sync(*chat.c);
        CHECK(chat.c->conversation(chat.convo, await)
                      ->messages(await)[0]
                      .attachments[0]
                      .availability == AttachmentAvailability::unreadable);
        CHECK(chat.owed() == 0);
    }
}

TEST_CASE("Client: a pointer with no url is never owed", "[client][auto][existing]") {
    Backlog chat;
    chat.set(AutoDownload::all);
    deliver(*chat.c,
            chat.peer,
            "",
            from_epoch_ms(chat.when++),
            "nourl",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_size(100);
                a->set_contenttype("image/png");
            });
    sync(*chat.c);
    CHECK(chat.owed() == 0);
    CHECK(chat.fetching().empty());

    chat.fetch_existing();
    CHECK(chat.owed() == 0);
    chat.reopen(false);
    CHECK(chat.owed() == 0);
    CHECK(chat.fetching().empty());
}
