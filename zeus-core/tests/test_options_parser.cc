// tests/test_options_parser.cc
#include "zeus.hh"
#include <gtest/gtest.h>

using namespace zeus;

TEST(OptionsParser, ParsesLoginAndPasswordFiles)
{
    const char* argv[] = {"zeus", "-L", "logins.txt", "-P", "passwords.txt"};
    auto opts = OptionsParser::parse(5, const_cast<char**>(argv));
    ASSERT_TRUE(opts.login_file.has_value());
    EXPECT_EQ(*opts.login_file, "logins.txt");
    ASSERT_TRUE(opts.password_file.has_value());
    EXPECT_EQ(*opts.password_file, "passwords.txt");
}

TEST(OptionsParser, DebugFlagImpliesDebugLogLevel)
{
    const char* argv[] = {"zeus", "-d"};
    auto opts = OptionsParser::parse(2, const_cast<char**>(argv));
    EXPECT_EQ(opts.engine.log_level, LogLevel::debug);
}

TEST(OptionsParser, DefaultTasksIsSixteen)
{
    const char* argv[] = {"zeus"};
    auto opts = OptionsParser::parse(1, const_cast<char**>(argv));
    EXPECT_EQ(opts.tasks, 16);
}

TEST(OptionsParser, ExplicitTasksOverridesDefault)
{
    const char* argv[] = {"zeus", "-t", "4"};
    auto opts = OptionsParser::parse(3, const_cast<char**>(argv));
    EXPECT_EQ(opts.tasks, 4);
}