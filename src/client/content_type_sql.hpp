#pragma once

#include <session/sqlite.hpp>
#include <string_view>

namespace session::client {

// Registers `session_displayable_image(content_type)` on `c`, which is image::is_displayable_image
// itself rather than a translation of it into SQL: SQLite's string functions disagree with each
// other, and with C++, on bytes that are not valid UTF-8.  Every connection that runs
// `DISPLAYABLE_IMAGE_SQL` needs it.
void register_content_type_functions(sqlite::Connection& c);

// True when `content_type` is one Session displays as an image; NULL for a NULL one.
inline constexpr std::string_view DISPLAYABLE_IMAGE_SQL = "session_displayable_image(content_type)";

}  // namespace session::client
