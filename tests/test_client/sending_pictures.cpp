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

// What a sent attachment should be: re-encoded, or the file as it is, flagged or not.
enum class Sent { converted, as_is, original_file };

struct Case {
    const char* name;
    bytes file;
    bool original_file;
    std::string_view type;  // as sent
    std::string_view sent_name;
    Sent sent;
};

}  // namespace

TEST_CASE(
        "Client: pictures go out re-encoded, everything else as it is",
        "[client][send][pictures]") {
    using namespace image_test;
    TempClient c;
    auto* net = attach_mock_network(c->core);
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

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

    std::vector<Case> cases{
            {"photo.jpg", photo, false, "image/jpeg", "photo.jpg", Sent::converted},
            {"logo.png", logo, false, "image/webp", "logo.webp", Sent::converted},
            {"spin.gif", spin, false, "image/webp", "spin.webp", Sent::converted},
            {"notes.pdf",
             bytes(300, std::byte{1}),
             false,
             "application/pdf",
             "notes.pdf",
             Sent::as_is},
            {"untouched.jpg", photo, true, "image/jpeg", "untouched.jpg", Sent::original_file},
            {"shot.heic",
             bytes{heic.begin(), heic.end()},
             false,
             heic_converts ? "image/jpeg" : "image/heic",
             heic_converts ? "shot.jpg" : "shot.heic",
             heic_converts ? Sent::converted : Sent::original_file},
    };

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_pictures", 7);
    std::filesystem::create_directories(dir);
    OutgoingMessage out;
    for (auto& cs : cases) {
        write_all(dir / cs.name, cs.file);
        out.attachments.push_back({.path = dir / cs.name, .original_file = cs.original_file});
    }

    auto id = c->send_message(ConversationId::dm(me), std::move(out), await);
    // One upload at a time, each after its own trip through the disk and derive loops.
    REQUIRE(derived_test::eventually([&] {
        sync(*c);
        return accept_stores(*net) == 1;
    }));
    auto msg = c->message(id, await);
    REQUIRE(msg);
    REQUIRE(msg->attachments.size() == cases.size());

    for (size_t i = 0; i < cases.size(); i++) {
        const auto& cs = cases[i];
        const auto& a = msg->attachments[i];
        INFO(cs.name);
        CHECK(a.content_type == cs.type);
        CHECK(a.filename == cs.sent_name);
        CHECK(a.original_file == (cs.sent == Sent::original_file));

        bytes expected = cs.file;
        if (cs.sent == Sent::converted) {
            image::Source src{std::span<const std::byte>{cs.file}};
            expected = image::sendable(src, 10'000'000)->bytes;
        }
        CHECK(a.size == static_cast<int64_t>(expected.size()));

        // What the file server holds, read back the way a recipient would.
        auto dest = dir / "saved-{}"_format(i);
        std::promise<std::optional<Error>> done;
        c->Client::save_attachment(id, i, dest, nullptr, [&done](auto r) {
            done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
        });
        sync(*c);
        REQUIRE(serve_downloads(*net) == 1);
        REQUIRE(done.get_future().get() == std::nullopt);
        CHECK(!!(read_all(dest) == expected));
        // The application's file is never rewritten.
        CHECK(!!(read_all(dir / cs.name) == cs.file));
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: a picture that cannot fit the file server is not sent",
        "[client][send][pictures]") {
    TempClient c;
    network::config::Config config;
    config.custom_file_server_max_file_size = 2'000;
    attach_mock_network(c->core, config);
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_pictures", 7);
    std::filesystem::create_directories(dir);
    write_all(dir / "photo.jpg", derived_test::picture(640, 480, ".jpg"));

    std::optional<std::string_view> code;
    auto id = c->send_message(
            ConversationId::dm(me),
            {.attachments = {OutgoingAttachment{.path = dir / "photo.jpg"}}},
            [&](size_t, int64_t, int64_t, std::optional<Expected<void>> r) {
                if (r && !*r)
                    code = r->error().code;
            },
            await);
    sync(*c);
    CHECK(code == err::attachment_too_large);
    CHECK(c->message(id, await)->send_state == SendState::unsendable);
    std::filesystem::remove_all(dir);
}
