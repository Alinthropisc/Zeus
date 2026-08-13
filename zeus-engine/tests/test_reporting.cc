
#include "../lib/zeus_engine.hh"
#include <gtest/gtest.h>
#include <memory>

using namespace zeus;

namespace
{
    class CountingSink final : public ReportSink
    {
        public:
            void on_found(const Finding&) override
            {
                ++count;
            }
            int count = 0;
    };
} // namespace

TEST(CompositeReportSink, ForwardsToEverySubscribedSink)
{
    CompositeReportSink composite;
    auto sink_a = std::make_shared<CountingSink>();
    auto sink_b = std::make_shared<CountingSink>();
    composite.add(sink_a);
    composite.add(sink_b);

    composite.on_found(Finding{22, "ssh", "10.0.0.1", "root", "toor", std::nullopt});

    EXPECT_EQ(sink_a->count, 1);
    EXPECT_EQ(sink_b->count, 1);
}

TEST(CompositeReportSink, EmptyCompositeDoesNothingSafely)
{
    CompositeReportSink composite;
    EXPECT_NO_THROW(composite.on_found(Finding{80, "http", "10.0.0.2", std::nullopt, std::nullopt, std::nullopt}));
}

TEST(FileReportSink, WritesExpectedFieldsToFile)
{
    std::FILE* f = std::tmpfile();
    ASSERT_NE(f, nullptr);
    FileReportSink sink(f, /*colored=*/false);
    sink.on_found(Finding{5432, "postgres", "192.168.1.10", "postgres", "hunter2", std::nullopt});
    std::rewind(f);
    char line[256] = {};
    ASSERT_NE(std::fgets(line, sizeof(line), f), nullptr);
    std::string s(line);
    EXPECT_NE(s.find("[5432][postgres]"), std::string::npos);
    EXPECT_NE(s.find("host: 192.168.1.10"), std::string::npos);
    EXPECT_NE(s.find("login: postgres"), std::string::npos);
    EXPECT_NE(s.find("password: hunter2"), std::string::npos);
    std::fclose(f);
}

TEST(FileReportSink, OmitsOptionalFieldsWhenAbsent)
{
    std::FILE* f = std::tmpfile();
    ASSERT_NE(f, nullptr);
    FileReportSink sink(f, false);
    sink.on_found(Finding{23, "telnet", "10.0.0.5", std::nullopt, std::nullopt, std::nullopt});
    std::rewind(f);
    char line[256] = {};
    std::fgets(line, sizeof(line), f);
    std::string s(line);
    EXPECT_EQ(s.find("login:"), std::string::npos);
    EXPECT_EQ(s.find("password:"), std::string::npos);
    std::fclose(f);
}