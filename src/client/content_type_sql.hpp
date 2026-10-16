#pragma once

#include <session/image/content_types.hpp>
#include <string>
#include <string_view>

namespace session::client {

// The SQL counterparts of image::mime_essence() and image::is_displayable_image(), built from the
// same constants so the two cannot drift apart.  SQLite's lower() folds only ASCII, which is also
// all the C++ side folds.  Neither can use an index on `column`.
inline std::string mime_essence_sql(std::string_view column) {
    std::string col{column}, ws;
    for (char c : image::mime_whitespace)
        ws += (ws.empty() ? "" : ",") + std::to_string(static_cast<int>(c));
    return "trim(substr(" + col + ", 1, instr(" + col + " || ';', ';') - 1), char(" + ws + "))";
}

inline std::string displayable_image_sql(std::string_view column) {
    std::string sql = "lower(" + mime_essence_sql(column) + ") IN (";
    for (auto type : image::displayable_image_types)
        (sql += '\'').append(type) += "',";
    sql.back() = ')';
    return sql;
}

}  // namespace session::client
