#include <catch2/catch_test_macros.hpp>
#include <session/core.hpp>
#include <session/network/session_network.hpp>

#include "utils.hpp"

using namespace session;

TEST_CASE("Core can hold an optional Network interface", "[core][network]") {
    core::callbacks callbacks;
    auto db_path = std::filesystem::temp_directory_path() / "test_core_network.db";
    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);

    core::Core core{db_path, callbacks};

    SECTION("Network is initially null") {
        CHECK(core.network() == nullptr);
    }

    SECTION("Network can be set and retrieved") {
        auto network = std::make_unique<network::Network>(network::config::Config{});
        auto* attached = network.get();
        core.set_network(std::move(network));
        CHECK(core.network() == attached);
    }

    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);
}

TEST_CASE("A file server's size limit keeps its full width", "[core][network]") {
    // Past 16 bits, as every real limit is.
    network::config::Config config{network::opt::file_server_max_file_size{10'000'000}};
    CHECK(config.custom_file_server_max_file_size == 10'000'000);
}
