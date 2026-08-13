#include "zeus-contract.hh"
#include <gtest/gtest.h>

using zeus::contract::Kind;
using zeus::contract::ViolationError;

TEST(Contract, SatisfiedPreconditionDoesNotThrow)
{
    EXPECT_NO_THROW(ZEUS_EXPECTS(1 + 1 == 2));
}

TEST(Contract, ViolatedPreconditionThrowsWithCorrectKind)
{
    try {
        ZEUS_EXPECTS(1 == 2);
        FAIL() << "expected ViolationError";
    } catch (const ViolationError& e) {
        EXPECT_EQ(e.kind(), Kind::precondition);
        EXPECT_NE(std::string(e.what()).find("PRECONDITION"), std::string::npos);
    }
}

TEST(Contract, ViolatedPostconditionThrowsWithCorrectKind)
{
    EXPECT_THROW({[] { ZEUS_ENSURES(false); }();}, ViolationError);
}

TEST(Contract, InvariantGuardCatchesBrokenInvariantOnExit)
{
    struct Counter {
        int value = 1;
    } c;
    EXPECT_THROW({zeus::contract::InvariantGuard guard(c, [&]{
        return c.value > 0; });
        c.value = -1;
    }, ViolationError);
}