
#include "zeus.hh"
#include <gtest/gtest.h>

using namespace zeus;

TEST(TargetExpander, SinglePlainHostProducesOneTarget)
{
    Options opts;
    opts.server = "10.0.0.5";
    opts.service = "ssh";
    auto targets = TargetExpander::expand(opts);
    ASSERT_EQ(targets.size(), 1u);
    EXPECT_EQ(targets[0].host, "10.0.0.5");
    EXPECT_EQ(targets[0].port, 22); // resolved from ServiceCatalog's ssh descriptor
}

TEST(TargetExpander, Slash24CidrProduces254UsableHosts)
{
    Options opts;
    opts.server = "192.168.1.0/24";
    opts.service = "ssh";
    auto targets = TargetExpander::expand(opts);
    EXPECT_EQ(targets.size(), 254u); // network + broadcast excluded
}

TEST(TargetExpander, Ipv6BracketNotationIsPreservedVerbatim)
{
    Options opts;
    opts.server = "[2001:db8::1]";
    opts.service = "http-get";
    auto targets = TargetExpander::expand(opts);
    ASSERT_EQ(targets.size(), 1u);
    EXPECT_EQ(targets[0].host, "2001:db8::1");
}

TEST(TargetExpander, EveryTargetStartsInActiveState)
{
    Options opts;
    opts.server = "10.0.0.1";
    opts.service = "ftp";
    auto targets = TargetExpander::expand(opts);
    for (auto& t : targets) EXPECT_EQ(t.state, TargetState::active);
}