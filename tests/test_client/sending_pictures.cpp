#include <libheif/heif.h>

#include <session/client/error_codes.hpp>
#include <session/image/sendable.hpp>

#include "../image_drawing.hpp"
#include "../image_fixtures.hpp"
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

void write_all(const std::filesystem::path& p, const bytes& b) {
    std::ofstream{p, std::ios::binary}.write(reinterpret_cast<const char*>(b.data()), b.size());
}

bool heic_decodes() {
#ifdef __APPLE__
    return true;
#else
    return heif_have_decoder_for_format(heif_compression_HEVC);
#endif
}

bytes converted(const bytes& file) {
    image::Source src{std::span<const std::byte>{file}};
    return image::sendable(src, 10'000'000)->bytes;
}

// What the file server holds for attachment `i`, read back the way a recipient would.
bytes read_back(TempClient& c, MockNetwork& net, int64_t id, size_t i, std::filesystem::path dest) {
    std::promise<std::optional<Error>> done;
    c->Client::save_attachment(id, i, dest, nullptr, [&done](auto r) {
        done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
    });
    sync(*c);
    REQUIRE(serve_downloads(net) == 1);
    REQUIRE(done.get_future().get() == std::nullopt);
    return read_all(dest);
}

// The uploads go one at a time, each after its own trip through the disk and derive loops.
void until(TempClient& c, const std::function<bool()>& done) {
    REQUIRE(derived_test::eventually([&] {
        sync(*c);
        return done();
    }));
}

// What the file server holds for attachment `i`: decrypted from what the upload left there.
bytes on_server(TempClient& c, MockNetwork& net, int64_t id, size_t i) {
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

struct Sandbox {
    TempCacheDir cache;
    TempClient c;
    MockNetwork* net;
    std::filesystem::path dir =
            std::filesystem::temp_directory_path() / random::unique_id("test_pictures", 7);
    explicit Sandbox(network::config::Config config = {}) :
            net{attach_mock_network(c->core, std::move(config))} {
        TestHelper::seed_pfs_nak(c->core, own_sid(*c));
        std::filesystem::create_directories(dir);
    }
    ~Sandbox() { std::filesystem::remove_all(dir); }
    std::filesystem::path write(std::string_view name, const bytes& b) {
        write_all(dir / name, b);
        return dir / name;
    }
};

// What a sent attachment should be: re-encoded, or the file as it is, flagged or not.
enum class Sent { converted, as_is, original_file };

struct Case {
    const char* name;
    bytes file;
    bool original_file;
    std::string_view type;  // as sent
    std::string_view sent_name;
    Sent sent;
    uint32_t width = 0, height = 0;  // as sent, 0 for none
    bool thumbhash = false;
    std::optional<std::string> declared = std::nullopt;  // the caller's content type, if any
};

}  // namespace

TEST_CASE(
        "Client: pictures go out re-encoded, everything else as it is",
        "[client][send][pictures]") {
    using namespace image_test;
    Sandbox s;
    s.c->set_cache_dir(s.cache.path);
    auto photo = derived_test::picture(640, 480, ".jpg");
    auto logo =
            save(draw(
                         64, 48, [](int x, int) { return rgba{0, 0, 255, uint8_t(x * 4)}; }, 4)
                         .get(),
                 ".png");
    auto spin = save(
            draw(
                    40, 30, [](int x, int y) { return rgba{uint8_t(x), uint8_t(y), 0, 255}; }, 3, 3)
                    .get(),
            ".gif");
    std::span<const std::byte> heic{image_fixtures::heic_64x48};
    const bool heic_converts = heic_decodes();

    // clang-format off
    std::vector<Case> cases{
        {"photo.jpg", photo, false, "image/jpeg", "photo.jpg", Sent::converted, 640, 480, true},
        {"logo.png", logo, false, "image/webp", "logo.webp", Sent::converted, 64, 48, true},
        {"spin.gif", spin, false, "image/webp", "spin.webp", Sent::converted, 40, 30, true},
        {"notes.pdf", bytes(300, std::byte{1}), false, "application/pdf", "notes.pdf", Sent::as_is},
        {"untouched.jpg", photo, true, "image/jpeg", "untouched.jpg", Sent::original_file, 640, 480, true},
        {"wave.png", animated_png(derived_test::picture(64, 48, ".png")), false, "image/png", "wave.png", Sent::original_file, 64, 48, true},
        {"wave.apng", animated_png(derived_test::picture(64, 48, ".png")), false, "image/apng", "wave.apng", Sent::original_file, 0, 0, false, "image/apng"},
        // A content type's parameters, case and spacing do not stop the placeholder being read.
        {"kept.jpg", photo, true, " IMAGE/JPEG ; charset=binary", "kept.jpg", Sent::original_file, 640, 480, true, " IMAGE/JPEG ; charset=binary"},
        // A picture type libvips does not read: shown as a file, sent as it is.
        {"scan.tiff", bytes(64, std::byte{'I'}), false, "image/tiff", "scan.tiff", Sent::original_file},
        // Its type inferred from the extension, so it says it is a picture, but does not read as one.
        {"broken.avif", bytes(64, std::byte{'A'}), false, "image/avif", "broken.avif", Sent::original_file},
        {"shot.heic", bytes{heic.begin(), heic.end()}, false,
         heic_converts ? "image/jpeg" : "image/heic", heic_converts ? "shot.jpg" : "shot.heic",
         heic_converts ? Sent::converted : Sent::original_file,
         heic_converts ? 64u : 0u, heic_converts ? 48u : 0u, heic_converts},
    };
    // clang-format on

    OutgoingMessage out;
    for (auto& cs : cases)
        out.attachments.push_back(
                {.path = s.write(cs.name, cs.file),
                 .content_type = cs.declared,
                 .original_file = cs.original_file});
    auto id = s.c->send_message(ConversationId::dm(own_sid(*s.c)), std::move(out), await);
    until(s.c, [&] { return accept_stores(*s.net) == 1; });
    auto msg = s.c->message(id, await);
    REQUIRE(msg);
    REQUIRE(msg->attachments.size() == cases.size());

    for (size_t i = 0; i < cases.size(); i++) {
        const auto& cs = cases[i];
        const auto& a = msg->attachments[i];
        INFO(cs.name);
        CHECK(a.content_type == cs.type);
        CHECK(a.filename == cs.sent_name);
        CHECK(a.original_file == (cs.sent == Sent::original_file));
        CHECK(a.width.value_or(0) == cs.width);
        CHECK(a.height.value_or(0) == cs.height);
        CHECK(a.thumbhash.has_value() == cs.thumbhash);

        auto expected = cs.sent == Sent::converted ? converted(cs.file) : cs.file;
        CHECK(a.size == static_cast<int64_t>(expected.size()));
        CHECK(!!(on_server(s.c, *s.net, id, i) == expected));
        // Kept here too, whatever it is: the only copy of what went out once the server's expires.
        CHECK(!!(s.c->attachment_data_cached(id, i, await) == expected));
        // The application's file is never rewritten.
        CHECK(!!(read_all(s.dir / cs.name) == cs.file));

        // Told beforehand, from the header alone, what the send then did.
        if (cs.original_file)
            continue;
        auto plan = s.c->attachment_send_plan(s.dir / cs.name, cs.declared, await);
        switch (cs.sent) {
            case Sent::converted: CHECK(plan == image::SendPlan::reencoded); break;
            case Sent::as_is: CHECK(plan == image::SendPlan::as_is); break;
            case Sent::original_file:
                CHECK(plan == (std::string_view{cs.name}.starts_with("wave.")
                                       ? image::SendPlan::original_animated_png
                                       : image::SendPlan::original_cannot_decode));
                break;
        }
    }
}

TEST_CASE(
        "Client: a picture is never sent as it is when its re-encode fails",
        "[client][send][pictures]") {
    std::vector<std::string_view> codes;
    auto report = [&](size_t, int64_t, int64_t, std::optional<Expected<void>> r) {
        if (r && !*r)
            codes.push_back(r->error().code);
    };
    auto send = [&](Sandbox& s, const std::filesystem::path& p) {
        return s.c->send_message(
                ConversationId::dm(own_sid(*s.c)),
                {.attachments = {OutgoingAttachment{.path = p}}},
                report,
                await);
    };
    auto state = [](Sandbox& s, int64_t id) { return s.c->message(id, await)->send_state; };

    SECTION("a picture whose header reads and whose pixels do not fails, to be tried again") {
        Sandbox s;
        // The first image data byte broken, so its chunk's CRC no longer matches.
        auto damaged = derived_test::picture(64, 48, ".png");
        auto idat = std::string_view{reinterpret_cast<const char*>(damaged.data()), damaged.size()}
                            .find("IDAT");
        REQUIRE(idat != std::string_view::npos);
        damaged[idat + 4] ^= std::byte{0xFF};
        // Only decoding it finds that out.
        CHECK(s.c->attachment_send_plan(s.write("damaged.png", damaged), std::nullopt, await) ==
              image::SendPlan::reencoded);
        auto id = send(s, s.dir / "damaged.png");
        until(s.c, [&] { return state(s, id) == SendState::failed; });
        CHECK(codes == std::vector<std::string_view>{err::attachment_unreadable});
        CHECK(s.net->served.empty());
        CHECK_FALSE(s.c->message(id, await)->attachments[0].original_file);
    }

    SECTION("a picture whose header is damaged fails the same way, EXIF and all kept home") {
        Sandbox s;
        // Cut before its frame header, after everything a camera puts ahead of it.
        auto photo = derived_test::picture(64, 48, ".jpg");
        auto sof = std::string_view{reinterpret_cast<const char*>(photo.data()), photo.size()}.find(
                "\xFF\xC2"sv);
        if (sof == std::string_view::npos)
            sof = std::string_view{reinterpret_cast<const char*>(photo.data()), photo.size()}.find(
                    "\xFF\xC0"sv);
        REQUIRE(sof != std::string_view::npos);
        photo.resize(sof);
        CHECK(s.c->attachment_send_plan(s.write("cut.jpg", photo), std::nullopt, await) ==
              image::SendPlan::unreadable);
        auto id = send(s, s.dir / "cut.jpg");
        until(s.c, [&] { return state(s, id) == SendState::failed; });
        CHECK(codes == std::vector<std::string_view>{err::attachment_unreadable});
        CHECK(s.net->served.empty());
    }

    SECTION("a picture past the decode limits is refused, not sent as it is") {
        Sandbox s;
        std::span<const std::byte> avif{image_fixtures::avif8_4900x4900};
        CHECK(s.c->attachment_send_plan(
                      s.write("huge.avif", bytes{avif.begin(), avif.end()}), std::nullopt, await) ==
              image::SendPlan::too_large_to_decode);
        auto id = send(s, s.dir / "huge.avif");
        until(s.c, [&] { return state(s, id) == SendState::unsendable; });
        CHECK(codes == std::vector<std::string_view>{err::attachment_too_large});
        CHECK(s.net->served.empty());
    }

    SECTION("a failed upload is retried, the picture re-encoded the same") {
        Sandbox s;
        auto photo = derived_test::picture(640, 480, ".jpg");
        s.net->failing_uploads = 1;
        auto id = send(s, s.write("photo.jpg", photo));
        until(s.c, [&] { return state(s, id) == SendState::failed; });
        s.c->retry_send(id, await);
        until(s.c, [&] { return accept_stores(*s.net) == 1; });
        CHECK(!!(read_back(s.c, *s.net, id, 0, s.dir / "saved") == converted(photo)));
    }

    SECTION("a picture that cannot fit the file server fails for good") {
        network::config::Config config;
        config.custom_file_server_max_file_size = 2'000;
        Sandbox s{config};
        // Only re-encoding it finds that it cannot be made small enough.
        CHECK(s.c->attachment_send_plan(
                      s.write("photo.jpg", derived_test::picture(640, 480, ".jpg")),
                      std::nullopt,
                      await) == image::SendPlan::reencoded);
        auto photo = send(s, s.dir / "photo.jpg");
        until(s.c, [&] { return state(s, photo) == SendState::unsendable; });
        // Not a picture, so nothing can make it smaller.
        CHECK(s.c->attachment_send_plan(
                      s.write("big.pdf", bytes(3000, std::byte{1})), std::nullopt, await) ==
              image::SendPlan::too_large_for_server);
        CHECK(s.c->attachment_send_plan(s.dir / "big.pdf", "IMAGE/PNG; x=y", await) ==
              image::SendPlan::too_large_for_server);
        auto pdf = send(s, s.dir / "big.pdf");
        until(s.c, [&] { return state(s, pdf) == SendState::unsendable; });
        CHECK(codes ==
              std::vector<std::string_view>{err::attachment_too_large, err::attachment_too_large});
        CHECK(s.net->served.empty());
    }
}

TEST_CASE("Client: a send plan for a file that is not there", "[client][send][pictures]") {
    Sandbox s;
    CHECK(s.c->attachment_send_plan(s.dir / "nothing.jpg", std::nullopt, await) ==
          image::SendPlan::missing);
    CHECK(s.c->attachment_send_plan(s.dir, std::nullopt, await) == image::SendPlan::missing);

    // The handler form answers the same, read on the disk thread.
    std::promise<Expected<image::SendPlan>> got;
    s.c->attachment_send_plan(
            s.write("photo.jpg", derived_test::picture(64, 48, ".jpg")), std::nullopt, [&](auto r) {
                got.set_value(std::move(r));
            });
    auto r = got.get_future().get();
    REQUIRE(r);
    CHECK(*r == image::SendPlan::reencoded);
}

TEST_CASE(
        "Client: the file server's limit holds a file sent as it is once encrypted",
        "[client][send][pictures]") {
    // The default limit, 10,000,000 bytes, on what is uploaded.
    constexpr size_t fits = 9'956'278;
    REQUIRE(attachment::encrypted_size(fits) <= 10'000'000);
    REQUIRE(attachment::encrypted_size(fits + 1) > 10'000'000);

    Sandbox s;
    std::vector<std::string_view> codes;
    auto send = [&](const std::filesystem::path& p) {
        return s.c->send_message(
                ConversationId::dm(own_sid(*s.c)),
                {.attachments = {OutgoingAttachment{.path = p}}},
                [&](size_t, int64_t, int64_t, std::optional<Expected<void>> r) {
                    if (r && !*r)
                        codes.push_back(r->error().code);
                },
                await);
    };
    auto state = [&](int64_t id) { return s.c->message(id, await)->send_state; };

    auto small = s.write("small.bin", bytes(fits, std::byte{1}));
    auto big = s.write("big.bin", bytes(fits + 1, std::byte{1}));
    CHECK(s.c->attachment_send_plan(small, std::nullopt, await) == image::SendPlan::as_is);
    CHECK(s.c->attachment_send_plan(big, std::nullopt, await) ==
          image::SendPlan::too_large_for_server);

    auto refused = send(big);
    until(s.c, [&] { return state(refused) == SendState::unsendable; });
    CHECK(codes == std::vector<std::string_view>{err::attachment_too_large});
    CHECK(s.net->served.empty());

    send(small);
    until(s.c, [&] { return accept_stores(*s.net) == 1; });
    CHECK(codes.size() == 1);
}
