#pragma once

#include <oxenc/hex.h>
#include <sodium.h>
#include <sodium/crypto_scalarmult_ed25519.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "session/config/base.h"
#include "session/util.hpp"

using ustring = std::basic_string<unsigned char>;
using ustring_view = std::basic_string_view<unsigned char>;

inline ustring operator""_bytes(const char* x, size_t n) {
    return {reinterpret_cast<const unsigned char*>(x), n};
}
inline ustring operator""_hexbytes(const char* x, size_t n) {
    ustring bytes;
    oxenc::from_hex(x, x + n, std::back_inserter(bytes));
    return bytes;
}

inline std::string to_hex(ustring_view bytes) {
    std::string hex;
    oxenc::to_hex(bytes.begin(), bytes.end(), std::back_inserter(hex));
    return hex;
}

inline constexpr auto operator""_kiB(unsigned long long kiB) {
    return kiB * 1024;
}

inline int64_t get_timestamp_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
}

inline std::string_view to_sv(ustring_view x) {
    return {reinterpret_cast<const char*>(x.data()), x.size()};
}
inline ustring_view to_usv(std::string_view x) {
    return {reinterpret_cast<const unsigned char*>(x.data()), x.size()};
}
template <size_t N>
ustring_view to_usv(const std::array<unsigned char, N>& data) {
    return {data.data(), N};
}

inline std::string printable(ustring_view x) {
    std::string p;
    for (auto c : x) {
        if (c >= 0x20 && c <= 0x7e)
            p += c;
        else
            p += "\\x" + oxenc::to_hex(&c, &c + 1);
    }
    return p;
}
inline std::string printable(std::string_view x) {
    return printable(to_usv(x));
}
std::string printable(const unsigned char* x) = delete;
inline std::string printable(const unsigned char* x, size_t n) {
    return printable({x, n});
}

template <typename Container>
std::set<typename Container::value_type> as_set(const Container& c) {
    return {c.begin(), c.end()};
}

template <typename... T>
std::set<std::common_type_t<T...>> make_set(T&&... args) {
    return {std::forward<T>(args)...};
}

template <typename C>
std::vector<std::basic_string_view<C>> view_vec(std::vector<std::basic_string<C>>&& v) = delete;
template <typename C>
std::vector<std::basic_string_view<C>> view_vec(const std::vector<std::basic_string<C>>& v) {
    std::vector<std::basic_string_view<C>> vv;
    vv.reserve(v.size());
    std::copy(v.begin(), v.end(), std::back_inserter(vv));
    return vv;
}

inline std::string random_point_on_ed25519() {
    if (sodium_init() == -1)
        throw std::runtime_error{"Failed to initialize libsodium!"};

    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char ed25519_skpk[crypto_sign_ed25519_SECRETKEYBYTES];

    crypto_sign_ed25519_keypair(ed25519_pk, ed25519_skpk);

    char hex[crypto_sign_ed25519_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), ed25519_pk, 32);

    auto pk_unsigned = session::to_unsigned_sv(hex);
    auto pk = std::string{to_sv(pk_unsigned)};
    if (!crypto_core_ed25519_is_valid_point(ed25519_pk)) {
        throw std::invalid_argument{
                "random_point_on_ed25519: '" + pk + "' is not on the ed25519 curve."};
    }

    return pk;
}

inline std::string random_point_on_x25519() {
    if (sodium_init() == -1)
        throw std::runtime_error{"Failed to initialize libsodium!"};

    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char ed25519_skpk[crypto_sign_ed25519_SECRETKEYBYTES];
    unsigned char x25519_pk[crypto_scalarmult_curve25519_BYTES];

    crypto_sign_ed25519_keypair(ed25519_pk, ed25519_skpk);

    if (crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk) != 0) {
        throw std::invalid_argument("crypto_sign_ed25519_pk_to_curve25519 failed");
    }
    char hex[crypto_scalarmult_curve25519_BYTES * 2 + 1] = {0};

    sodium_bin2hex(hex, sizeof(hex), x25519_pk, sizeof(x25519_pk));

    return std::string{hex};
}

inline std::string random_05_pubkey() {
    return "05" + random_point_on_x25519();
}

inline std::string random_03_pubkey() {
    return "03" + random_point_on_ed25519();
}