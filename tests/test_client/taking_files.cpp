#include <session/client/error_codes.hpp>

#include "derived_fixture.hpp"

using namespace std::literals;

namespace {

using bytes = std::vector<std::byte>;

bytes read_all(const std::filesystem::path& p) {
    std::ifstream in{p, std::ios::binary};
    std::string raw{std::istreambuf_iterator<char>{in}, {}};
    auto* b = reinterpret_cast<const std::byte*>(raw.data());
    return {b, b + raw.size()};
}

bytes contents(size_t n) {
    bytes b(n);
    for (size_t i = 0; i < n; i++)
        b[i] = static_cast<std::byte>((i * 13 + i / 97) % 256);
    return b;
}

std::string stored_path(TempClient& c, int64_t id, size_t i = 0) {
    return c->core.loop().call_get([&] {
        return c->core.database().conn().prepared_get<std::string>(
                "SELECT path FROM message_attachments WHERE message = ? AND idx = ?",
                id,
                static_cast<int64_t>(i));
    });
}

// What the file server holds for attachment `i`, decrypted.
bytes on_server(TempClient& c, MockNetwork& net, int64_t id, size_t i = 0) {
    using key_t = std::array<std::byte, attachment::ENCRYPT_KEY_SIZE>;
    auto [url, key] = c->core.loop().call_get([&] {
        return c->core.database().conn().prepared_get<std::string, sqlite::blob_guts<key_t>>(
                "SELECT url, key FROM message_attachments WHERE message = ? AND idx = ?",
                id,
                static_cast<int64_t>(i));
    });
    auto file_id = url.substr(url.rfind('/') + 1);
    file_id = file_id.substr(0, file_id.find('#'));
    return attachment::decrypt(net.served.at(file_id), key);
}

size_t files_in(const std::filesystem::path& dir) {
    std::error_code ec;
    size_t n = 0;
    for ([[maybe_unused]] const auto& e : std::filesystem::directory_iterator{dir, ec})
        n++;
    return n;
}

bool eventually_gone(TempClient& c, const std::filesystem::path& p) {
    return derived_test::eventually([&] {
        sync(*c);
        return !std::filesystem::exists(p);
    });
}

struct Sandbox {
    TempCacheDir cache;
    TempClient c;
    b33 me;
    std::filesystem::path dir =
            std::filesystem::temp_directory_path() / random::unique_id("test_taking", 7);
    std::filesystem::path outgoing = cache.path / "outgoing";
    Sandbox() : me{own_sid(*c)} {
        TestHelper::seed_pfs_nak(c->core, me);
        std::filesystem::create_directories(dir);
        c->set_cache_dir(cache.path);
    }
    ~Sandbox() { std::filesystem::remove_all(dir); }
    std::filesystem::path write(std::string_view name, const bytes& b) {
        std::ofstream{dir / name, std::ios::binary}.write(
                reinterpret_cast<const char*>(b.data()), b.size());
        return dir / name;
    }
    int64_t send(const std::filesystem::path& file, bool take = true) {
        return c->send_message(
                ConversationId::dm(me),
                {.body = "here",
                 .attachments = {OutgoingAttachment{.path = file, .take_file = take}}},
                await);
    }
};

}  // namespace

TEST_CASE(
        "Client: a taken file is moved, uploaded from its copy, then removed",
        "[client][send][take]") {
    Sandbox s;
    auto* net = attach_mock_network(s.c->core);
    auto body = contents(70 * 1024);
    auto file = s.write("report.bin", body);

    auto id = s.send(file);
    CHECK_FALSE(std::filesystem::exists(file));
    sync(*s.c);
    REQUIRE(accept_stores(*net) == 1);

    auto msg = s.c->message(id, await);
    REQUIRE(msg);
    REQUIRE(msg->attachments.size() == 1);
    CHECK(msg->attachments[0].uploaded);
    CHECK(msg->attachments[0].filename == "report.bin");
    CHECK(msg->attachments[0].content_type == "application/octet-stream");
    CHECK(stored_path(s.c, id).starts_with("outgoing/"));
    CHECK(on_server(s.c, *net, id) == body);

    CHECK(derived_test::eventually([&] {
        sync(*s.c);
        return files_in(s.outgoing) == 0;
    }));
}

TEST_CASE("Client: a retry uploads the taken copy", "[client][send][take]") {
    Sandbox s;
    auto* net = attach_mock_network(s.c->core);
    net->failing_uploads = 1;
    auto body = contents(5000);
    auto file = s.write("notes.txt", body);

    auto id = s.send(file);
    sync(*s.c);
    REQUIRE(s.c->message(id, await)->send_state == SendState::failed);
    CHECK_FALSE(std::filesystem::exists(file));
    auto owned = s.cache.path / stored_path(s.c, id);
    REQUIRE(std::filesystem::exists(owned));

    REQUIRE(s.c->retry_send(id, await));
    sync(*s.c);
    REQUIRE(accept_stores(*net) == 1);
    CHECK(s.c->message(id, await)->attachments[0].uploaded);
    CHECK(s.c->message(id, await)->attachments[0].content_type == "text/plain");
    CHECK(on_server(s.c, *net, id) == body);
    CHECK(eventually_gone(s.c, owned));
}

TEST_CASE("Client: deleting a message removes the file it took", "[client][send][take]") {
    Sandbox s;
    auto file = s.write("draft.bin", contents(3000));

    // No network: the upload fails and the message keeps the file for a retry.
    auto id = s.send(file);
    sync(*s.c);
    REQUIRE(s.c->message(id, await)->send_state == SendState::failed);
    auto owned = s.cache.path / stored_path(s.c, id);
    REQUIRE(std::filesystem::exists(owned));

    REQUIRE(s.c->delete_message(id, await));
    CHECK(eventually_gone(s.c, owned));
}

TEST_CASE(
        "Client: clearing a conversation removes the files its messages took",
        "[client][send][take]") {
    Sandbox s;
    auto id = s.send(s.write("a.bin", contents(3000)));
    sync(*s.c);
    auto owned = s.cache.path / stored_path(s.c, id);
    REQUIRE(std::filesystem::exists(owned));

    // Clearing takes what is strictly older than now, so not a message sent this millisecond.
    std::this_thread::sleep_for(5ms);
    s.c->conversation(ConversationId::dm(s.me), await)->clear_messages(await);
    CHECK(eventually_gone(s.c, owned));
}

TEST_CASE("Client: a refused send leaves the caller's file where it was", "[client][send][take]") {
    Sandbox s;
    auto body = contents(3000);
    auto file = s.write("keep.bin", body);

    CHECK_THROWS_AS(
            s.c->send_message(
                    ConversationId::dm(s.me),
                    {.body = "re",
                     .attachments = {OutgoingAttachment{.path = file, .take_file = true}},
                     .reply_to = 987654},
                    await),
            std::invalid_argument);
    CHECK(read_all(file) == body);
    CHECK(files_in(s.outgoing) == 0);
}

TEST_CASE("Client: take_file needs a cache directory", "[client][send][take]") {
    TempClient c;
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);
    auto file = std::filesystem::temp_directory_path() / random::unique_id("test_take_nocache", 7);
    std::ofstream{file} << "contents";

    CHECK_THROWS_AS(
            c->send_message(
                    ConversationId::dm(me),
                    {.attachments = {OutgoingAttachment{.path = file, .take_file = true}}},
                    await),
            std::invalid_argument);
    CHECK(std::filesystem::exists(file));
    std::filesystem::remove(file);
}

TEST_CASE(
        "Client: the startup sweep keeps only taken files a message needs",
        "[client][send][take]") {
    Sandbox s;
    auto id = s.send(s.write("pending.bin", contents(3000)));
    sync(*s.c);
    REQUIRE(s.c->message(id, await)->send_state == SendState::failed);
    auto owned = s.cache.path / stored_path(s.c, id);

    // What a crash between taking a file and storing its message leaves.
    auto orphan = s.outgoing / "orphan.bin";
    std::ofstream{orphan} << "nobody needs this";

    s.c.reopen();
    s.c->set_cache_dir(s.cache.path);
    CHECK(eventually_gone(s.c, orphan));
    CHECK(std::filesystem::exists(owned));
}

TEST_CASE("Client: without take_file the caller's file is left alone", "[client][send][take]") {
    Sandbox s;
    auto* net = attach_mock_network(s.c->core);
    auto body = contents(4000);
    auto file = s.write("mine.bin", body);

    auto id = s.send(file, /*take=*/false);
    sync(*s.c);
    REQUIRE(accept_stores(*net) == 1);
    CHECK(s.c->message(id, await)->attachments[0].uploaded);
    CHECK(stored_path(s.c, id) == file.string());
    CHECK(read_all(file) == body);
    CHECK(files_in(s.outgoing) == 0);
}

TEST_CASE("Client: a taken file survives the cache directory moving", "[client][send][take]") {
    auto parent = std::filesystem::temp_directory_path() / random::unique_id("test_take_move", 7);
    auto before = parent / "container-a", after = parent / "container-b";
    std::filesystem::create_directories(before);
    TempClient c;
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);
    c->set_cache_dir(before);

    auto body = contents(4000);
    auto file = parent / "moving.bin";
    std::ofstream{file, std::ios::binary}.write(
            reinterpret_cast<const char*>(body.data()), body.size());
    auto id = c->send_message(
            ConversationId::dm(me),
            {.attachments = {OutgoingAttachment{.path = file, .take_file = true}}},
            await);
    sync(*c);
    REQUIRE(c->message(id, await)->send_state == SendState::failed);

    c.client.reset();
    std::filesystem::rename(before, after);
    c.reopen();
    c->set_cache_dir(after);
    auto* net = attach_mock_network(c->core);
    sync(*c);
    REQUIRE(files_in(after / "outgoing") == 1);

    REQUIRE(c->retry_send(id, await));
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);
    CHECK(c->message(id, await)->attachments[0].uploaded);
    CHECK(on_server(c, *net, id) == body);
    CHECK(derived_test::eventually([&] {
        sync(*c);
        return files_in(after / "outgoing") == 0;
    }));

    c.client.reset();
    std::filesystem::remove_all(parent);
}

TEST_CASE("Client: take_file refuses a symbolic link", "[client][send][take]") {
    Sandbox s;
    auto body = contents(3000);
    auto real = s.write("real.bin", body);
    auto link = s.dir / "link.bin";
    std::filesystem::create_symlink("real.bin", link);

    CHECK_THROWS_AS(s.send(link), std::invalid_argument);
    CHECK(std::filesystem::is_symlink(link));
    CHECK(read_all(link) == body);
    CHECK(read_all(real) == body);
    CHECK(files_in(s.outgoing) == 0);
}

TEST_CASE("Client: a taken file is served until it is uploaded", "[client][send][take]") {
    Sandbox s;
    auto body = contents(3000);
    auto id = s.send(s.write("photo.bin", body));
    sync(*s.c);
    REQUIRE(s.c->message(id, await)->send_state == SendState::failed);

    CHECK(s.c->message(id, await)->attachments[0].availability == AttachmentAvailability::cached);
    CHECK(s.c->attachment_data_cached(id, 0, await) == body);

    std::promise<Expected<std::vector<std::byte>>> got;
    s.c->attachment_data(id, 0, nullptr, [&](auto r) { got.set_value(std::move(r)); });
    auto answer = got.get_future();
    REQUIRE(derived_test::eventually([&] {
        sync(*s.c);
        return answer.wait_for(0s) == std::future_status::ready;
    }));
    auto r = answer.get();
    REQUIRE(r);
    CHECK(*r == body);
}

TEST_CASE("Client: a taken file goes when its message turns unsendable", "[client][send][take]") {
    Sandbox s;
    network::config::Config config;
    config.custom_file_server_max_file_size = 2'000;
    attach_mock_network(s.c->core, std::move(config));

    auto id = s.send(s.write("big.bin", contents(3000)));
    auto owned = s.cache.path / stored_path(s.c, id);
    CHECK(derived_test::eventually([&] {
        sync(*s.c);
        return s.c->message(id, await)->send_state == SendState::unsendable;
    }));
    CHECK(eventually_gone(s.c, owned));
    CHECK(s.c->message(id, await)->attachments[0].availability == AttachmentAvailability::absent);
    CHECK_THROWS(s.c->attachment_data_cached(id, 0, await));
}

TEST_CASE("Client: a sweep keeps a file taken for a send not yet stored", "[client][send][take]") {
    Sandbox s;
    auto body = contents(3000);
    auto file = s.write("racing.bin", body);
    OutgoingMessage msg{.attachments = {OutgoingAttachment{.path = file, .take_file = true}}};
    auto taken = TestHelper::take_files(*s.c, msg);
    auto copy = s.cache.path / msg.attachments[0].path;
    REQUIRE(std::filesystem::exists(copy));

    TestHelper::sweep_outgoing(*s.c);
    sync(*s.c);
    CHECK(std::filesystem::exists(copy));

    // Dropped without its message being stored: the copy goes and the caller's file stays.
    taken.reset();
    CHECK_FALSE(std::filesystem::exists(copy));
    CHECK(read_all(file) == body);
}

TEST_CASE(
        "Client: a taken file is saved from our copy until it is uploaded",
        "[client][send][take]") {
    Sandbox s;
    auto body = contents(3000);
    auto id = s.send(s.write("keepsake.bin", body));
    sync(*s.c);
    REQUIRE(s.c->message(id, await)->send_state == SendState::failed);

    std::promise<Expected<std::filesystem::path>> done;
    s.c->save_attachment(
            id, 0, s.dir / "saved.bin", nullptr, [&](auto r) { done.set_value(std::move(r)); });
    auto answer = done.get_future();
    REQUIRE(derived_test::eventually([&] {
        sync(*s.c);
        return answer.wait_for(0s) == std::future_status::ready;
    }));
    auto saved = answer.get();
    REQUIRE(saved);
    CHECK(read_all(*saved) == body);
}
