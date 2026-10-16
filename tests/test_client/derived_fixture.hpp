#pragma once

// One conversation that fetches everything it is sent, over a mock network, with a cache, and the
// pictures and probes the derived-image tests share.

#include <vips/vips.h>

#include <session/client/error_codes.hpp>
#include <session/image/thumbnail.hpp>
#include <session/image/vips.hpp>
#include <session/network/backends/session_file_server.hpp>

#include "../../src/client/download_cache.hpp"
#include "../utils.hpp"
#include "common.hpp"

namespace cache = session::client::cache;

namespace derived_test {

// A w x h picture, encoded as `suffix` says (".png", ".jpg"), in one colour with a stripe so that
// it compresses to something of a realistic size rather than to nothing.  `orientation` is written
// as the file's EXIF orientation, which only a JPEG carries.
inline std::vector<std::byte> picture(
        int w, int h, const char* suffix = ".png", int orientation = 1) {
    image::init();
    std::vector<uint8_t> px(size_t(w) * h * 3);
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            auto* p = &px[(size_t(y) * w + x) * 3];
            p[0] = uint8_t(x * 255 / w);
            p[1] = uint8_t(y * 255 / h);
            p[2] = (x / 16 + y / 16) % 2 ? 200 : 40;
        }
    VipsImage* img =
            vips_image_new_from_memory_copy(px.data(), px.size(), w, h, 3, VIPS_FORMAT_UCHAR);
    REQUIRE(img);
    if (orientation != 1)
        vips_image_set_int(img, VIPS_META_ORIENTATION, orientation);
    void* buf = nullptr;
    size_t len = 0;
    int rc = vips_image_write_to_buffer(img, suffix, &buf, &len, nullptr);
    g_object_unref(img);
    REQUIRE(rc == 0);
    std::vector<std::byte> out{static_cast<std::byte*>(buf), static_cast<std::byte*>(buf) + len};
    g_free(buf);
    return out;
}

// A w x h animation of `frames` frames, each a different shade so that the encoder keeps them
// apart, as `suffix` says (".gif", ".webp").
inline std::vector<std::byte> animation(int w, int h, int frames, const char* suffix) {
    image::init();
    std::vector<VipsImage*> shades;
    for (int i = 0; i < frames; i++) {
        VipsImage *black, *shade;
        REQUIRE(vips_black(&black, w, h, "bands", 3, nullptr) == 0);
        REQUIRE(vips_linear1(black, &shade, 1.0, 100.0 + 30 * i, "uchar", TRUE, nullptr) == 0);
        g_object_unref(black);
        shades.push_back(shade);
    }
    VipsImage* joined;
    int rc = vips_arrayjoin(shades.data(), &joined, frames, "across", 1, nullptr);
    for (auto* s : shades)
        g_object_unref(s);
    REQUIRE(rc == 0);
    VipsImage* img;
    rc = vips_copy(joined, &img, "interpretation", VIPS_INTERPRETATION_sRGB, nullptr);
    g_object_unref(joined);
    REQUIRE(rc == 0);
    vips_image_set_int(img, "page-height", h);
    void* buf = nullptr;
    size_t len = 0;
    rc = vips_image_write_to_buffer(img, suffix, &buf, &len, nullptr);
    g_object_unref(img);
    REQUIRE(rc == 0);
    std::vector<std::byte> out{static_cast<std::byte*>(buf), static_cast<std::byte*>(buf) + len};
    g_free(buf);
    return out;
}

// The width and height of an encoded JPEG.
inline std::pair<int, int> jpeg_size(const std::vector<std::byte>& jpeg) {
    REQUIRE(jpeg.size() > 2);
    CHECK(jpeg[0] == std::byte{0xFF});
    CHECK(jpeg[1] == std::byte{0xD8});
    VipsImage* img = vips_image_new_from_buffer(jpeg.data(), jpeg.size(), "", nullptr);
    REQUIRE(img);
    std::pair size{img->Xsize, img->Ysize};
    g_object_unref(img);
    return size;
}

inline bool eventually(const std::function<bool()>& done, std::chrono::milliseconds timeout = 20s) {
    auto until = std::chrono::steady_clock::now() + timeout;
    while (!done()) {
        if (std::chrono::steady_clock::now() > until)
            return false;
        std::this_thread::sleep_for(5ms);
    }
    return true;
}

// Waits until no thumbnail is queued or being made, and everything that finishing one posted has
// run.
inline void settle(Client& c) {
    sync(c);
    REQUIRE(eventually([&] { return TestHelper::thumbnails_idle(c); }));
    sync(c);
}

inline std::optional<std::string_view> error_code(const std::function<void()>& f) {
    try {
        f();
    } catch (const session::error& e) {
        return e.err().code;
    }
    return std::nullopt;
}

// One conversation that fetches everything it is sent, over a mock network, with a cache.
struct Fixture {
    TempCacheDir dir;
    Recorder rec;
    TempClient c;
    SenderKeys peer;
    ConversationId convo = ConversationId::dm(peer.session_id);
    MockNetwork* net;
    std::vector<std::byte> seed = random::random(32);
    int sent = 0;

    // Explicit `rec{}`, or Apple clang's -Wuninitialized flags its use in `c`'s initializer.
    template <ClientOption... Opts>
    explicit Fixture(Opts&&... opts) : rec{}, c{rec.handlers(), std::forward<Opts>(opts)...} {
        net = attach_mock_network(c->core);
        c->set_cache_dir(dir.path);
        c->open_dm(convo, await);
        c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);
    }

    // Delivers `data` as one attachment of `content_type`, lets it download, and returns the
    // message's id and the attachment's url.  Waits for its thumbnail too unless `thumbnails` is
    // false, for a Client whose thumbnails are stalled.
    std::pair<int64_t, std::string> arrive(
            std::span<const std::byte> data,
            std::string_view content_type = "image/png",
            bool thumbnails = true) {
        auto [ct, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
        auto file_id = "f{}"_format(sent);
        net->served[file_id] = ct;
        auto url = network::file_server::generate_download_url(file_id, {}, true);
        deliver(*c,
                peer,
                "",
                from_epoch_ms(1000 + sent),
                "h{}"_format(sent),
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(1);
                    a->set_url(url);
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(data.size());
                    a->set_contenttype(std::string{content_type});
                });
        sent++;
        sync(*c);
        REQUIRE(serve_downloads(*net) == 1);
        if (thumbnails)
            settle(*c);
        else
            REQUIRE(eventually([&] {
                auto msgs = c->conversation(convo, await)->messages(await);
                return msgs[0].attachments.at(0).availability == AttachmentAvailability::cached;
            }));
        return {c->conversation(convo, await)->messages(await)[0].id, url};
    }

    void reopen() {
        c.reopen();
        net = attach_mock_network(c->core);
        c->set_cache_dir(dir.path);
        settle(*c);
    }

    // What a cache filled by a version that made no thumbnails looks like: the file, and an entry
    // with no thumbnail.
    void strip_thumbnail(const std::string& url) {
        TestHelper::on_loop(c->core, [&] {
            c->core.database().conn().prepared_exec(
                    "DELETE FROM attachment_derived WHERE kind = 1"
                    " AND entry = (SELECT id FROM attachment_cache WHERE name = ?)",
                    file(url).filename().string());
        });
        std::filesystem::remove(thumb_file(url));
    }

    Attachment attachment(int64_t id) { return c->message(id, await)->attachments.at(0); }

    std::filesystem::path file(const std::string& url) {
        return TestHelper::cache_path(*c, cache::ATTACHMENT_DIR, url);
    }
    std::filesystem::path thumb_file(const std::string& url) {
        auto f = file(url);
        f += cache::THUMBNAIL_SUFFIX;
        return f;
    }

    template <typename T = int64_t, typename... Bind>
    T db_get(const std::string& query, const Bind&... bind) {
        return TestHelper::on_loop(
                c->core, [&] { return c->core.database().conn().prepared_get<T>(query, bind...); });
    }

    int64_t entry(const std::string& url) {
        return db_get(
                "SELECT id FROM attachment_cache WHERE name = ?", file(url).filename().string());
    }

    // The thumbnailer version the entry is recorded as refused under, or 0.
    int64_t refused_under(const std::string& url) {
        return db_get(
                "SELECT coalesce((SELECT d.failed FROM attachment_derived d"
                " WHERE d.entry = c.id AND d.kind = 1), 0) FROM attachment_cache c WHERE name = ?",
                file(url).filename().string());
    }
};

// Replaces a file's contents, as something outside libsession going wrong would.
inline void overwrite(const std::filesystem::path& file, std::span<const std::byte> data) {
    std::ofstream out{file, std::ios::binary | std::ios::trunc};
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
}

inline std::vector<std::byte> contents(const std::filesystem::path& file) {
    std::ifstream in{file, std::ios::binary};
    std::vector<char> bytes{std::istreambuf_iterator<char>{in}, {}};
    auto* p = reinterpret_cast<const std::byte*>(bytes.data());
    return {p, p + bytes.size()};
}

// A TestHelper hold, let go at the latest when this goes out of scope: declared after the Client
// it holds, so that a failing test does not leave the Client's teardown waiting on it.
struct Hold {
    std::shared_ptr<std::promise<void>> promise;
    bool released = false;
    void release() {
        if (!std::exchange(released, true))
            promise->set_value();
    }
    ~Hold() { release(); }
};

}  // namespace derived_test
