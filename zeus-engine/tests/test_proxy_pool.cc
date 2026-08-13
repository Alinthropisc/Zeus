
#include "../../zeus-core/lib/zeus_contract.hh"
#include "../lib/zeus_engine.hh"
#include <gtest/gtest.h>

using namespace zeus;

TEST(ZeusProxyPool, EmptyPoolReportsEmpty)
{
    ZeusProxyPool pool;
    EXPECT_TRUE(pool.empty());
}

TEST(ZeusProxyPool, AddingMakesPoolNonEmpty)
{
    ZeusProxyPool pool;
    pool.add(ZeusProxyConfig{ZeusProxyType::socks5, "127.0.0.1", 1080, std::nullopt, std::nullopt});
    EXPECT_FALSE(pool.empty());
}

TEST(ZeusProxyPool, PickRandomOnEmptyPoolViolatesContract)
{
    ZeusProxyPool pool;
    EXPECT_THROW(pool.pick_random(), zeus::contract::ZeusViolationError);
}

TEST(ZeusProxyPool, PickRandomAlwaysReturnsAKnownEntry)
{
    ZeusProxyPool pool;
    pool.add(ZeusProxyConfig{ZeusProxyType::socks4, "10.0.0.1", 1080, std::nullopt, std::nullopt});
    pool.add(ZeusProxyConfig{ZeusProxyType::socks5, "10.0.0.2", 1080, std::nullopt, std::nullopt});

    // Statistical smoke test: with enough draws, both entries should
    // eventually be selected (proves it's not stuck returning index 0).
    bool saw_first = false, saw_second = false;
    for (int i = 0; i < 200 && !(saw_first && saw_second); ++i)
    {
        const auto& picked = pool.pick_random();
        if (picked.host == "10.0.0.1")
        {
            saw_first = true;
        }
        if (picked.host == "10.0.0.2")
        {
            saw_second = true;
        }
        }
        EXPECT_TRUE(saw_first);
        EXPECT_TRUE(saw_second);
}