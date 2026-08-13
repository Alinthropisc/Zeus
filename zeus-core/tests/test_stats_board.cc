
#include "zeus.hh"
#include <gtest/gtest.h>
#include <thread>
#include <vector>

using namespace zeus;

TEST(StatsBoard, CountersStartAtZero)
{
    StatsBoard stats;
    EXPECT_EQ(stats.sent(), 0u);
    EXPECT_EQ(stats.found(), 0u);
}

TEST(StatsBoard, OnAttemptIncrementsSentByOne)
{
    StatsBoard stats;
    stats.on_attempt();
    stats.on_attempt();
    EXPECT_EQ(stats.sent(), 2u);
}

TEST(StatsBoard, IsThreadSafeUnderConcurrentIncrement)
{
    // Regression guard for the atomic counters — StatsBoard replaces the
    // original hydra_brain struct, which was mutated from multiple
    // forked children without any synchronization at all.
    StatsBoard stats;
    constexpr int kThreads = 8, kPerThread = 1000;
    std::vector<std::thread> workers;
    for (int i = 0; i < kThreads; ++i)
    workers.emplace_back([&] { for (int j = 0; j < kPerThread; ++j) stats.on_attempt(); });
    for (auto& t : workers) t.join();
    EXPECT_EQ(stats.sent(), static_cast<std::uint64_t>(kThreads * kPerThread));
}