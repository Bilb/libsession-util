#include <session/image/location.hpp>

#include "../location_fixture.hpp"
#include "derived_fixture.hpp"

using location_fixture::count_marks;
using location_fixture::exif_segment;
using location_fixture::exif_tiff;
using location_fixture::jpeg_with;

namespace {

std::vector<std::byte> read_all(const std::filesystem::path& p) {
    std::ifstream in{p, std::ios::binary};
    std::vector<char> raw{std::istreambuf_iterator<char>{in}, {}};
    std::vector<std::byte> out(raw.size());
    std::memcpy(out.data(), raw.data(), raw.size());
    return out;
}

}  // namespace

TEST_CASE(
        "Client: a picture goes out without its location, and the file is left as it was",
        "[client][send][location]") {
    TempCacheDir cache;
    TempClient c;
    auto* net = attach_mock_network(c->core);
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_location", 7);
    std::filesystem::create_directories(dir);
    auto photo = dir / "photo.jpg";
    auto original = jpeg_with({exif_segment(exif_tiff(true))});
    {
        std::ofstream out{photo, std::ios::binary};
        out.write(reinterpret_cast<const char*>(original.data()), original.size());
    }
    auto expected = image::without_location(original);
    REQUIRE(expected);
    REQUIRE(count_marks(*expected) == count_marks(original) - 28);

    SECTION("what is uploaded") {
        auto id = c->send_message(
                ConversationId::dm(me),
                {.attachments = {OutgoingAttachment{.path = photo, .content_type = "image/jpeg"}}},
                await);
        sync(*c);
        REQUIRE(accept_stores(*net) == 1);

        auto msg = c->message(id, await);
        REQUIRE(msg);
        CHECK(msg->attachments.at(0).uploaded);
        CHECK(msg->attachments.at(0).size == static_cast<int64_t>(expected->size()));

        auto dest = dir / "saved.jpg";
        std::promise<std::optional<Error>> done;
        c->Client::save_attachment(msg->id, 0, dest, nullptr, [&done](auto r) {
            done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
        });
        sync(*c);
        // From the file server, since nothing here was cached.
        REQUIRE(serve_downloads(*net) == 1);
        REQUIRE(done.get_future().get() == std::nullopt);
        CHECK(!!(read_all(dest) == *expected));
    }

    SECTION("what we keep of it") {
        c->set_cache_dir(cache.path);
        auto id = c->send_message(
                ConversationId::dm(me),
                {.attachments = {OutgoingAttachment{.path = photo, .content_type = "image/jpeg"}}},
                await);
        sync(*c);
        REQUIRE(accept_stores(*net) == 1);
        derived_test::settle(*c);

        REQUIRE(c->message(id, await)->attachments.at(0).availability ==
                AttachmentAvailability::cached);
        CHECK(!!(c->attachment_data_cached(id, 0, await) == *expected));
    }

    CHECK(!!(read_all(photo) == original));
    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: a picture that gets shorter is sent and kept at its new size",
        "[client][send][location]") {
    TempCacheDir cache;
    TempClient c;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(cache.path);
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_location", 7);
    std::filesystem::create_directories(dir);
    auto photo = dir / "photo.png";
    // A PNG whose XMP names a place: the chunk is dropped, so the file shrinks.
    auto original = location_fixture::saved("png");
    constexpr std::string_view xmp =
            "XML:com.adobe.xmp\0\0\0\0\0<exif:GPSLatitude>51</exif:GPSLatitude>"sv;
    std::vector<std::byte> chunk(4 + 4 + xmp.size() + 4);
    chunk[3] = static_cast<std::byte>(xmp.size());
    std::memcpy(chunk.data() + 4, "iTXt", 4);
    std::memcpy(chunk.data() + 8, xmp.data(), xmp.size());
    original.insert(original.begin() + 8 + 25, chunk.begin(), chunk.end());
    {
        std::ofstream out{photo, std::ios::binary};
        out.write(reinterpret_cast<const char*>(original.data()), original.size());
    }
    auto expected = image::without_location(original);
    REQUIRE(expected);
    REQUIRE(expected->size() < original.size());

    auto id = c->send_message(
            ConversationId::dm(me),
            {.attachments = {OutgoingAttachment{.path = photo, .content_type = "image/png"}}},
            await);
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);
    derived_test::settle(*c);

    auto a = c->message(id, await)->attachments.at(0);
    CHECK(a.size == static_cast<int64_t>(expected->size()));
    REQUIRE(a.availability == AttachmentAvailability::cached);
    CHECK(!!(c->attachment_data_cached(id, 0, await) == *expected));
    CHECK(!!(read_all(photo) == original));
    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: a file with no location goes out as it is", "[client][send][location]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_location", 7);
    std::filesystem::create_directories(dir);
    auto photo = dir / "photo.jpg";
    auto original = jpeg_with({exif_segment(exif_tiff(true, false))});
    {
        std::ofstream out{photo, std::ios::binary};
        out.write(reinterpret_cast<const char*>(original.data()), original.size());
    }

    auto id = c->send_message(
            ConversationId::dm(me),
            {.attachments = {OutgoingAttachment{.path = photo, .content_type = "image/jpeg"}}},
            await);
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);

    auto dest = dir / "saved.jpg";
    std::promise<std::optional<Error>> done;
    c->Client::save_attachment(id, 0, dest, nullptr, [&done](auto r) {
        done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
    });
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    REQUIRE(done.get_future().get() == std::nullopt);
    CHECK(!!(read_all(dest) == original));
    std::filesystem::remove_all(dir);
}
