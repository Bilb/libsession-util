#pragma once

// Pictures drawn for the image tests, and ways to look at what came out.

#include <oxenc/hex.h>
#include <vips/vips.h>

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <session/image/vips.hpp>
#include <session/random.hpp>
#include <string>
#include <vector>

#include "../src/image/vips_internal.hpp"

namespace image_test {

namespace image = session::image;
using image::detail::image_ptr;

using rgba = std::array<uint8_t, 4>;

constexpr rgba RED{255, 0, 0, 255}, BLUE{0, 0, 255, 255}, GREEN{0, 255, 0, 255};

// A w x h RGBA image (or RGB, if `bands` is 3) whose pixel at (x, y) is `px(x, y)`; `frames` of
// them stacked vertically, as libvips holds animation, frame `f` drawn by `px(x, y + f * h)`.
inline image_ptr draw(
        int w, int h, const std::function<rgba(int, int)>& px, int bands = 3, int frames = 1) {
    image::init();
    std::vector<uint8_t> data(size_t(w) * h * frames * bands);
    for (int y = 0; y < h * frames; y++)
        for (int x = 0; x < w; x++) {
            auto p = px(x, y);
            std::copy_n(p.begin(), bands, data.begin() + (size_t(y) * w + x) * bands);
        }
    VipsImage* raw = vips_image_new_from_memory_copy(
            data.data(), data.size(), w, h * frames, bands, VIPS_FORMAT_UCHAR);
    REQUIRE(raw);
    image_ptr raw_ptr{raw};
    VipsImage* out;
    REQUIRE(vips_copy(raw, &out, "interpretation", VIPS_INTERPRETATION_sRGB, nullptr) == 0);
    image_ptr img{out};
    if (frames > 1)
        vips_image_set_int(img.get(), "page-height", h);
    return img;
}

inline std::vector<std::byte> save(VipsImage* img, const char* suffix) {
    void* buf = nullptr;
    size_t len = 0;
    REQUIRE(vips_image_write_to_buffer(img, suffix, &buf, &len, nullptr) == 0);
    std::vector<std::byte> out{static_cast<std::byte*>(buf), static_cast<std::byte*>(buf) + len};
    g_free(buf);
    return out;
}

// Decoded to memory, so the pixels can be read and the buffer can go.
inline image_ptr decode_jpeg(const std::vector<std::byte>& jpeg) {
    VipsImage* img = vips_image_new_from_buffer(jpeg.data(), jpeg.size(), "", nullptr);
    REQUIRE(img);
    image_ptr lazy{img};
    std::string loader;
    if (const char* name; vips_image_get_string(img, "vips-loader", &name) == 0)
        loader = name;
    CHECK(loader == "jpegload_buffer");
    VipsImage* decoded = vips_image_copy_memory(img);
    REQUIRE(decoded);
    return image_ptr{decoded};
}

inline rgba pixel(VipsImage* img, int x, int y) {
    auto* p = VIPS_IMAGE_ADDR(img, x, y);
    return {p[0], p[1], p[2], 255};
}

// JPEG is lossy: a colour is right if every channel is near it.
inline bool near(rgba got, rgba want, int tolerance = 24) {
    for (int c = 0; c < 3; c++)
        if (std::abs(int(got[c]) - int(want[c])) > tolerance)
            return false;
    return true;
}

inline bool has_marker(const std::vector<std::byte>& jpeg, uint8_t marker) {
    // Markers before the scan only: entropy-coded data can contain anything.
    for (size_t i = 2; i + 4 <= jpeg.size();) {
        if (jpeg[i] != std::byte{0xFF})
            return false;
        auto m = static_cast<uint8_t>(jpeg[i + 1]);
        if (m == marker)
            return true;
        if (m == 0xDA)
            return false;
        i += 2 + ((size_t(jpeg[i + 2]) << 8) | size_t(jpeg[i + 3]));
    }
    return false;
}

struct temp_file {
    std::filesystem::path path =
            std::filesystem::temp_directory_path() /
            ("libsession-image-test-" + oxenc::to_hex(session::random::random(8)));
    ~temp_file() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
};

}  // namespace image_test
