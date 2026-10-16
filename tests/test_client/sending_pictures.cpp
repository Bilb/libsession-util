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

struct Sandbox {
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

// A PNG made an APNG by an animation control chunk ahead of its image data.
bytes animated_png(bytes png) {
    bytes chunk{std::byte{0}, std::byte{0}, std::byte{0}, std::byte{8}};
    for (char c : "acTL\0\0\0\x02\0\0\0\0"sv)
        chunk.push_back(std::byte(c));
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 4; i < chunk.size(); i++) {
        crc ^= uint8_t(chunk[i]);
        for (int k = 0; k < 8; k++)
            crc = (crc & 1) ? 0xEDB88320u ^ (crc >> 1) : crc >> 1;
    }
    crc ^= 0xFFFFFFFFu;
    for (int shift : {24, 16, 8, 0})
        chunk.push_back(std::byte(crc >> shift));
    constexpr size_t after_ihdr = 8 + 25;
    png.insert(png.begin() + after_ihdr, chunk.begin(), chunk.end());
    return png;
}

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
};

}  // namespace

TEST_CASE(
        "Client: pictures go out re-encoded, everything else as it is",
        "[client][send][pictures]") {
    using namespace image_test;
    Sandbox s;
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
        // A picture type libvips does not read: shown as a file, sent as it is.
        {"scan.tiff", bytes(64, std::byte{'I'}), false, "image/tiff", "scan.tiff", Sent::original_file},
        {"shot.heic", bytes{heic.begin(), heic.end()}, false,
         heic_converts ? "image/jpeg" : "image/heic", heic_converts ? "shot.jpg" : "shot.heic",
         heic_converts ? Sent::converted : Sent::original_file,
         heic_converts ? 64u : 0u, heic_converts ? 48u : 0u, heic_converts},
    };
    // clang-format on

    OutgoingMessage out;
    for (auto& cs : cases)
        out.attachments.push_back(
                {.path = s.write(cs.name, cs.file), .original_file = cs.original_file});
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
        CHECK(!!(read_back(s.c, *s.net, id, i, s.dir / "saved-{}"_format(i)) == expected));
        // The application's file is never rewritten.
        CHECK(!!(read_all(s.dir / cs.name) == cs.file));
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
        auto id = send(s, s.write("damaged.png", damaged));
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
        auto id = send(s, s.write("cut.jpg", photo));
        until(s.c, [&] { return state(s, id) == SendState::failed; });
        CHECK(codes == std::vector<std::string_view>{err::attachment_unreadable});
        CHECK(s.net->served.empty());
    }

    SECTION("a picture past the decode limits is refused, not sent as it is") {
        Sandbox s;
        std::span<const std::byte> avif{image_fixtures::avif8_4900x4900};
        auto id = send(s, s.write("huge.avif", bytes{avif.begin(), avif.end()}));
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
        auto photo = send(s, s.write("photo.jpg", derived_test::picture(640, 480, ".jpg")));
        until(s.c, [&] { return state(s, photo) == SendState::unsendable; });
        // Not a picture, so nothing can make it smaller.
        auto pdf = send(s, s.write("big.pdf", bytes(3000, std::byte{1})));
        until(s.c, [&] { return state(s, pdf) == SendState::unsendable; });
        CHECK(codes ==
              std::vector<std::string_view>{err::attachment_too_large, err::attachment_too_large});
        CHECK(s.net->served.empty());
    }
}
