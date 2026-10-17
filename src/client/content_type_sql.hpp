#pragma once

#include <session/sqlite.hpp>
#include <string>
#include <string_view>

namespace session::client {

// Registers `session_displayable_image(content_type)` on `c`, which is image::is_displayable_image
// itself rather than a translation of it into SQL: SQLite's string functions disagree with each
// other, and with C++, on bytes that are not valid UTF-8.  Every connection that runs
// `displayable_image_sql` needs it.
void register_content_type_functions(sqlite::Connection& c);

// True when `column` is a content type Session displays as an image; NULL for a NULL one.
inline std::string displayable_image_sql(std::string_view column) {
    return "session_displayable_image(" + std::string{column} + ")";
}

}  // namespace session::client
