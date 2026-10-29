#pragma once
#include <filesystem>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

// Utility functions for working with files

namespace session {

namespace fs = std::filesystem;

/// Opens a file for writing of binary data, setting up the returned ofstream with exceptions
/// enabled for any failures.  This also throws if the file cannot be opened.  If the file already
/// exists it will be truncated.
std::ofstream open_for_writing(const fs::path& filename);

/// Opens a file for reading of binary data, setting up the returned ifstream with exceptions
/// enabled for any failures.  This also throws if the file cannot be opened.
std::ifstream open_for_reading(const fs::path& filename);

/// Reads a (binary) file from disk.
std::vector<std::byte> read_whole_file(const fs::path& filename);

/// Dumps (binary) string contents to disk. The file is overwritten if it already exists.
void write_whole_file(const fs::path& filename, std::string_view contents = "");

/// Waits until what is written to `path`, a file or a directory's entries, is on the storage
/// device rather than in a cache.  A directory is a no-op on Windows, which cannot open one for
/// this.  Throws std::system_error on failure.
void sync_to_disk(const fs::path& path);

/// A path as UTF-8, the form one is stored and logged in.  `path::string()` is the ANSI code page
/// on Windows, which cannot represent every name and throws for one it cannot; on POSIX the two
/// are the same bytes.
inline std::string utf8_string(const fs::path& p) {
    auto s = p.u8string();
    return {reinterpret_cast<const char*>(s.data()), s.size()};
}

/// The path that `utf8_string` gave `s` for.
inline fs::path utf8_path(std::string_view s) {
    return fs::path{std::u8string_view{reinterpret_cast<const char8_t*>(s.data()), s.size()}};
}

}  // namespace session
