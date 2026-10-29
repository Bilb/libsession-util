#include <fstream>
#include <session/file.hpp>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#endif

namespace session {

std::ofstream open_for_writing(const fs::path& filename) {
    std::ofstream out;
    out.exceptions(std::ios_base::failbit | std::ios_base::badbit);
    out.open(filename, std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
    out.exceptions(std::ios_base::badbit);
    return out;
}

std::ifstream open_for_reading(const fs::path& filename) {
    std::ifstream in;
    in.exceptions(std::ios_base::failbit | std::ios_base::badbit);
    in.open(filename, std::ios::binary | std::ios::in);
    in.exceptions(std::ios_base::badbit);
    return in;
}

std::vector<std::byte> read_whole_file(const fs::path& filename) {
    auto in = open_for_reading(filename);
    in.seekg(0, std::ios::end);
    auto size = in.tellg();
    in.seekg(0, std::ios::beg);

    if (size <= 0)
        return {};

    std::vector<std::byte> contents(static_cast<size_t>(size));
    if (!in.read(reinterpret_cast<char*>(contents.data()), size))
        return {};

    return contents;
}

void write_whole_file(const fs::path& filename, std::string_view contents) {
    auto out = open_for_writing(filename);
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

void sync_to_disk(const fs::path& path) {
#ifdef _WIN32
    if (fs::is_directory(path))
        return;
    HANDLE h = CreateFileW(
            path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
    if (h == INVALID_HANDLE_VALUE)
        throw std::system_error{
                static_cast<int>(GetLastError()), std::system_category(), "sync_to_disk: open"};
    BOOL flushed = FlushFileBuffers(h);
    DWORD err = GetLastError();
    CloseHandle(h);
    if (!flushed)
        throw std::system_error{static_cast<int>(err), std::system_category(), "sync_to_disk"};
#else
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        throw std::system_error{errno, std::generic_category(), "sync_to_disk: open"};
#ifdef __APPLE__
    // Apple's fsync stops at the drive's own cache; F_FULLFSYNC reaches the medium, where the
    // file system supports it.
    int r = ::fcntl(fd, F_FULLFSYNC);
    if (r == -1)
        r = ::fsync(fd);
#else
    int r = ::fsync(fd);
#endif
    int err = errno;
    ::close(fd);
    if (r == -1)
        throw std::system_error{err, std::generic_category(), "sync_to_disk"};
#endif
}

}  // namespace session
