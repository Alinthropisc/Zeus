#include <cstdio>
#include <string>
#include <gtest/gtest.h>

#include "../lib/zeus_engine.hh"


namespace
{

    std::string slurp(std::FILE* f)
    {
        std::rewind(f);
        std::string out;
        char buf[256];
        size_t n;

        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
        {
            out.append(buf, n);
        }
        return out;
    }

} // namespace

TEST(ZeusLogger, DebugMessagesAreSuppressedAtNormalLevel)
{
    zeus::ZeusLogger log(zeus::ZeusLogLevel::normal);
    EXPECT_FALSE(log.is_debug());
    EXPECT_FALSE(log.is_verbose());
}

TEST(ZeusLogger, DebugLevelEnablesBothDebugAndVerbose)
{
    zeus::ZeusLogger log(zeus::ZeusLogLevel::debug);
    EXPECT_TRUE(log.is_debug());
    EXPECT_TRUE(log.is_verbose());
}

TEST(ZeusLogger, SetLevelChangesGatingAtRuntime)
{
    zeus::ZeusLogger log(zeus::ZeusLogLevel::quiet);
    log.set_level(zeus::ZeusLogLevel::verbose);
    EXPECT_TRUE(log.is_verbose());
    EXPECT_FALSE(log.is_debug());
}

TEST(ZeusLoggerHexDump, EmptyTitleOmitsHeaderLine)
{
    std::FILE* f = std::tmpfile();
    ASSERT_NE(f, nullptr);
    std::array<std::byte, 3> data{std::byte{0x41}, std::byte{0x42}, std::byte{0x43}};
    zeus::ZeusLogger::hex_dump(data, "", f);
    auto out = slurp(f);
    EXPECT_EQ(out.find("bytes):"), std::string::npos);
    std::fclose(f);
}

TEST(LoggerHexDump, PrintableBytesShownAsCharsInBracketColumn)
{
    std::FILE* f = std::tmpfile();
    ASSERT_NE(f, nullptr);
    std::array<std::byte, 3> data{std::byte{'A'}, std::byte{'B'}, std::byte{'C'}};
    zeus::ZeusLogger::hex_dump(data, "test", f);
    auto out = slurp(f);
    EXPECT_NE(out.find("414243"), std::string::npos); // hex bytes present
    EXPECT_NE(out.find("[ ABC"), std::string::npos);   // ASCII column present
    std::fclose(f);
}

TEST(LoggerHexDump, NonPrintableBytesRenderAsDot)
{
    std::FILE* f = std::tmpfile();
    ASSERT_NE(f, nullptr);
    std::array<std::byte, 2> data{std::byte{0x00}, std::byte{0x01}};
    zeus::ZeusLogger::hex_dump(data, "", f);
    auto out = slurp(f);
    EXPECT_NE(out.find(".."), std::string::npos);
    std::fclose(f);
}