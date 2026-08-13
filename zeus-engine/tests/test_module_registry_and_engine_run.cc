
#include "../lib/zeus_engine.hh"
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <vector>

using namespace zeus;

namespace
{

    class RecordingModule final : public ZeusServices
    {
        public:
            std::string_view name() const noexcept override
            {
                return "recording-fake";
            }

            void init(ZeusEngine&) override
            {
                init_called = true;
            }

            void try_login(ZeusEngine& engine, std::string_view login, std::string_view password) override
            {
                calls.emplace_back(std::string{login}, std::string{password});

                if (login == "admin" && password == "correct")
                {
                    engine.report_success("fake", "127.0.0.1", std::string{login}, std::string{password});
                }

                if (login == "trigger" && password == "no-connect")
                {
                    engine.exit_worker(ZeusExitCode::no_connect);
                }
            }
            bool init_called = false;
            std::vector<std::pair<std::string, std::string>> calls;
    };

/// Simulates the parent process side: writes a fixed sequence of
/// credential pairs, expects one ack byte per pair, then sends the
/// HYDRA_EXIT sentinel to make Engine::run() return.
    void drive_parent_side(int fd, const std::vector<std::pair<std::string, std::string>>& pairs)
    {
        for (auto& [login, pass] : pairs)
        {
            std::string wire = login + '\0' + pass + '\0';
            ::write(fd, wire.data(), wire.size());
            char ack = 0;
            ::read(fd, &ack, 1);           // wait for 'N' or 'F' before sending next pair

            if (ack == 'F')
            {
                char buf[64] = {};
                ::read(fd, buf, sizeof(buf)); // consume the echoed login after a find
            }
        }
        static constexpr std::array<char, 5> exit_sentinel{char(0x00), char(0xff), char(0x00), char(0xff), char(0x00)};
        ::write(fd, exit_sentinel.data(), exit_sentinel.size());
    }

} // namespace

TEST(ZeusServicesRegistry, RegisterAndCreateRoundTrips)
{
    ZeusServicesRegistry::instance().register_service("test-echo-module", [] {
        return std::make_unique<RecordingModule>();
    });
    auto module = ZeusServicesRegistry::instance().create("test-echo-module");
    ASSERT_NE(module, nullptr);
    EXPECT_EQ(module->name(), "recording-fake");
}

TEST(ZeusServicesRegistry, UnknownNameReturnsNullptr)
{
    EXPECT_EQ(ZeusServicesRegistry::instance().create("does-not-exist-xyz"), nullptr);
}


TEST(ZeusAutoRegister, SelfRegistersAtStaticInitTime)
{
    // Declared here (rather than at namespace scope) purely to keep the
    // registration local to this test binary; in production code this
    // lives next to the concrete Module definition, as shown in earlier
    // examples (zeus-postgres.cc etc.).
    static zeus::ZeusAutoRegister<RecordingModule> reg{"auto-registered-fake"};
    auto module = ZeusServicesRegistry::instance().create("auto-registered-fake");
    ASSERT_NE(module, nullptr);
}

TEST(ZeusEngineRun, CallsInitExactlyOnceBeforeAnyTryLogin)
{
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    std::thread parent(drive_parent_side, fds[1], std::vector<std::pair<std::string, std::string>>{{"a", "b"}});
    ZeusCompositeReportSink reporter;
    ZeusEngine engine(ZeusEngine::Options{}, ZeusIpcChannel{fds[0]}, std::move(reporter));
    RecordingModule module;
    engine.run(module);
    parent.join();
    EXPECT_TRUE(module.init_called);
}

TEST(ZeusEngineRun, DispatchesEveryPairFromParentInOrder)
{
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    std::vector<std::pair<std::string, std::string>> pairs{{"user1", "pass1"}, {"user2", "pass2"}, {"admin", "correct"}};
    std::thread parent(drive_parent_side, fds[1], pairs);
    ZeusCompositeReportSink reporter;
    ZeusEngine engine(ZeusEngine::Options{}, ZeusIpcChannel{fds[0]}, std::move(reporter));
    RecordingModule module;
    engine.run(module);
    parent.join();
    ASSERT_EQ(module.calls.size(), 3u);
    EXPECT_EQ(module.calls[0], std::make_pair(std::string("user1"), std::string("pass1")));
    EXPECT_EQ(module.calls[2], std::make_pair(std::string("admin"), std::string("correct")));
}

TEST(ZeusEngineRun, SuccessfulFindReportsThroughCompositeSink)
{
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    std::thread parent(drive_parent_side, fds[1], std::vector<std::pair<std::string, std::string>>{{"admin", "correct"}});

    struct CapturingSink final : ZeusReportSink {
        void on_found(const Finding& f) override { captured = f; }
        std::optional<Finding> captured;
    };
    auto sink = std::make_shared<CapturingSink>();
    ZeusCompositeReportSink reporter;
    reporter.add(sink);
    ZeusEngine engine(ZeusEngine::Options{}, ZeusIpcChannel{fds[0]}, std::move(reporter));
    RecordingModule module;
    engine.run(module);
    parent.join();
    ASSERT_TRUE(sink->captured.has_value());
    EXPECT_EQ(sink->captured->login, "admin");
    EXPECT_EQ(sink->captured->password, "correct");
}

TEST(ZeusEngineRun, ExitWorkerPropagatesEngineExitToCaller)
{
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    // Note: since try_login() throws before acking, drive_parent_side's
    // blocking read() for the ack would hang forever for this pair —
    // so this scenario is driven manually rather than via the helper.
    std::string wire = std::string("trigger") + '\0' + "no-connect" + '\0';
    ::write(fds[1], wire.data(), wire.size());

    ZeusCompositeReportSink reporter;
    ZeusEngine engine(ZeusEngine::Options{}, ZeusIpcChannel{fds[0]}, std::move(reporter));
    RecordingModule module;

    EXPECT_THROW(engine.run(module), ZeusEngineExit);
    ::close(fds[1]);
}

TEST(ZeusEngineExit, CarriesTheExitCodeItWasConstructedWith)
{
    try {
        throw ZeusEngineExit(ZeusExitCode::protocol_error);
    } catch (const ZeusEngineExit& e) {
        EXPECT_EQ(e.code(), ZeusExitCode::protocol_error);
    }
}