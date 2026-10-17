#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <optional>
#include <session/format.hpp>
#include <session/image/content_types.hpp>
#include <session/random.hpp>
#include <session/sqlite.hpp>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "../../src/client/content_type_sql.hpp"
#include "common.hpp"

using namespace session;
using namespace std::literals;

namespace {

// Each with whether Session displays it as an image.
const std::vector<std::pair<std::string, bool>> content_types{
        {"image/jpeg", true},
        {"IMAGE/JPEG", true},
        {"Image/Png", true},
        {"image/jpeg; charset=binary", true},
        {"IMAGE/PNG ; foo=bar", true},
        {"image/png;", true},
        {"image/png;image/jpeg", true},
        {"imagE/pNg; q=\"a;b\"", true},
        {" image/png", true},
        {"image/png ", true},
        {"\timage/webp\t", true},
        {"image/gif\r\n", true},
        {" \t\r\nimage/avif \t\r\n; x=y", true},
        {"image/apng", false},
        {"IMAGE/APNG; charset=binary", false},
        {"image/jpg", true},
        {"image/pjpeg", true},
        {"", false},
        {" ", false},
        {";", false},
        {"; image/png", false},
        {"image/jpegx", false},
        {"image/jpeg2000", false},
        {"image/jp", false},
        {"image/pngx", false},
        {"image/png x", false},
        {"image /png", false},
        {"image/ png", false},
        {"xImage/png", false},
        {"image/svg+xml", false},
        {"image/heic", false},
        {"image/bmp", false},
        {"image/tiff", false},
        {"application/octet-stream", false},
        {"text/plain; image/png", false},
        {"image/png\v", false},
        {"\fimage/png", false},
        {"\xc2\xa0image/png", false},
        {"\xc4\xb0MAGE/PNG", false},
        {"image/png\0"s, false},
        {"image/png\0;"s, false},
        {"image/png\0x"s, false},
        {"image/pngx\0"s, false},
        // Stray UTF-8 continuation bytes, which SQLite's instr and substr count differently.
        {"image/png\x80", false},
        {"image/png\xbf", false},
        {"image/png \x80;", false},
        {"image/png\x80;x", false},
        {"image/jpeg\x80\x80;", false},
        {"\x80image/png", false},
        {"image/png;\x80", true},
        {"image/png ;\xff\xfe", true},
};

struct TempDb {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
                                 "{}.db"_format(random::unique_id("test_content_types", 7));
    sqlite::Database db{path, sqlite::post_open{client::register_content_type_functions}};

    ~TempDb() {
        std::error_code ec;
        for (auto suffix : {"", "-wal", "-shm"})
            std::filesystem::remove(path.string() + suffix, ec);
    }
};

}  // namespace

TEST_CASE("content types: the C++ check and its SQL counterpart agree", "[client][content_type]") {
    TempDb t;
    auto c = t.db.conn();
    c.sql.exec("CREATE TABLE t (id INTEGER PRIMARY KEY NOT NULL, ct TEXT)");
    for (const auto& [ct, _] : content_types)
        c.prepared_exec("INSERT INTO t (ct) VALUES (?)", ct);
    c.sql.exec("INSERT INTO t (ct) VALUES (NULL)");

    size_t i = 0;
    for (auto&& [ct, displayable] :
         c.prepared_results<std::optional<std::string>, std::optional<int>>(
                 "SELECT ct, {} FROM t ORDER BY id"_format(client::displayable_image_sql("ct")))) {
        if (!ct) {
            CHECK_FALSE(displayable);
            continue;
        }
        REQUIRE(i < content_types.size());
        const auto& [want_ct, want] = content_types[i++];
        INFO('"' << want_ct << '"');
        CHECK(*ct == want_ct);
        CHECK(image::is_displayable_image(want_ct) == want);
        REQUIRE(displayable);
        CHECK((*displayable != 0) == want);
    }
    CHECK(i == content_types.size());
}

TEST_CASE(
        "content types: every connection a Client opens has the SQL function",
        "[client][content_type]") {
    std::atomic<int> theirs = 0;
    TempClient c{sqlite::post_open{[&](sqlite::Connection&) { ++theirs; }}};
    auto ask = [&] {
        return c->core.database().conn().prepared_get<int>(
                "SELECT {}"_format(client::displayable_image_sql("'IMAGE/PNG; x=y'")));
    };
    CHECK(ask() == 1);
    int other = 0;
    std::thread{[&] { other = ask(); }}.join();
    CHECK(other == 1);
    // The application's own post_open still runs, on each of them.
    CHECK(theirs >= 2);
}

TEST_CASE(
        "content types: the essence drops parameters and surrounding whitespace only",
        "[client][content_type]") {
    CHECK(image::mime_essence(" IMAGE/PNG ; foo=bar") == "IMAGE/PNG");
    CHECK(image::mime_essence("image/jpeg") == "image/jpeg");
    CHECK(image::mime_essence("a b ; c") == "a b");
    CHECK(image::mime_essence(" ; x").empty());
    CHECK(image::mime_essence("").empty());
    static_assert(image::is_displayable_image("Image/JPEG; charset=binary"));
    static_assert(!image::is_displayable_image("image/jpeg2000"));
}
