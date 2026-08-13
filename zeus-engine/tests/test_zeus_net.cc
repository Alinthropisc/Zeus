
#include "../lib/zeus_net.hh"
#include <gtest/gtest.h>

using namespace zeus::net;
using namespace std::chrono_literals;

TEST(FixedRetryPolicy, StopsAfterMaxAttempts)
{
    ZeusFixedRetryPolicy policy(2, 100ms);
    EXPECT_EQ(policy.next_delay(1), 100ms);
    EXPECT_EQ(policy.next_delay(2), 100ms);
    EXPECT_EQ(policy.next_delay(3), std::nullopt); // give up
}

TEST(FixedRetryPolicy, RejectsInvalidAttemptNumber)
{
    FixedRetryPolicy policy(2, 100ms);
    EXPECT_THROW(policy.next_delay(0), zeus::contract::ViolationError);
}

TEST(ExponentialBackoffRetry, DelayGrowsAndIsCapped)
{
    ExponentialBackoffRetry policy(10, 10ms, 100ms);
    auto d1 = *policy.next_delay(1);
    auto d2 = *policy.next_delay(2);
    auto d5 = *policy.next_delay(5);
    EXPECT_LT(d1, d2);
    EXPECT_LE(d5, 100ms); // never exceeds the cap
}

TEST(RateLimiter, ConstructorRejectsNonPositiveRate)
{
    EXPECT_THROW(RateLimiter(0.0, 1), zeus::contract::ViolationError);
}

TEST(RateLimiter, AllowsBurstThenThrottles)
{
    RateLimiter limiter(/*rate=*/1000.0, /*burst=*/5);
    auto start = std::chrono::steady_clock::now();

    for (int i = 0; i < 5; ++i)
    {
        limiter.acquire(); // burst: should be near-instant
    }
    auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, 50ms);
}

TEST(ConnectionPool, RejectsZeroCapacity)
{
    EXPECT_THROW(ConnectionPool(0), zeus::contract::ViolationError);
}