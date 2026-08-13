
#include "zeus.hh"
#include <gtest/gtest.h>
#include <filesystem>

using namespace zeus;

TEST(RestoreSession, SaveThenLoadRoundTripsServerAndService)
{
    Options opts;
    opts.server = "192.168.1.1";
    opts.service = "ssh";
    opts.tasks = 8;

    std::vector<Target> targets{Target{.host = "192.168.1.1", .port = 22}};
    StatsBoard stats;

    auto path = std::filesystem::temp_directory_path() / "zeus_test_restore.bin";
    RestoreSession session;
    session.save(path, opts, targets, stats);

    auto loaded = RestoreSession::load(path);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->options.server, "192.168.1.1");
    EXPECT_EQ(loaded->options.service, "ssh");
    EXPECT_EQ(loaded->options.tasks, 8);
    ASSERT_EQ(loaded->targets.size(), 1u);
    EXPECT_EQ(loaded->targets[0].port, 22);

    std::filesystem::remove(path);
}

TEST(RestoreSession, LoadingMissingFileReturnsNulloptNotThrow)
{
    auto result = RestoreSession::load("/nonexistent/path/zeus.restore");
    EXPECT_FALSE(result.has_value());
}

TEST(RestoreSession, LoadingFileWithWrongMagicIsRejected)
{
    auto path = std::filesystem::temp_directory_path() / "zeus_test_bad_magic.bin";
    {
        std::ofstream f(path, std::ios::binary); f << "NOT-A-ZEUS-FILE";
    }

    auto result = RestoreSession::load(path);
    EXPECT_FALSE(result.has_value());

    std::filesystem::remove(path);
}