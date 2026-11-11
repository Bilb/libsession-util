#include "content_type_sql.hpp"

#include <SQLiteCpp/Database.h>
#include <sqlite3.h>

#include <session/image/content_types.hpp>
#include <stdexcept>

namespace session::client {

using namespace std::literals;

namespace {

    void displayable_image(sqlite3_context* ctx, int, sqlite3_value** argv) {
        if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
            return sqlite3_result_null(ctx);
        // Text before bytes: sqlite3_value_bytes is the length of what the last conversion made.
        auto* text = reinterpret_cast<const char*>(sqlite3_value_text(argv[0]));
        auto size = static_cast<size_t>(sqlite3_value_bytes(argv[0]));
        sqlite3_result_int(ctx, text && image::is_displayable_image({text, size}));
    }

}  // namespace

void register_content_type_functions(sqlite::Connection& c) {
    if (sqlite3_create_function_v2(
                c.sql.getHandle(),
                "session_displayable_image",
                1,
                SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_INNOCUOUS,
                nullptr,
                displayable_image,
                nullptr,
                nullptr,
                nullptr) != SQLITE_OK)
        throw std::runtime_error{
                "Cannot register session_displayable_image: "s + sqlite3_errmsg(c.sql.getHandle())};
}

}  // namespace session::client
