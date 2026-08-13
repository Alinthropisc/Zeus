#include <csignal>
#include <gtest/gtest.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../lib/zeus.hh"


using namespace zeus;

TEST(ZeusSignalGuard, SigtermTriggersGracefulShutdownNotDefaultTermination)
{
    pid_t pid = fork();
    ASSERT_NE(pid, -1);

    if (pid == 0)
    {
        // Child: install guard, then just wait to be signalled.
        Options opts; opts.server = "127.0.0.1"; opts.service = "smoke-fake";
        auto targets = ZeusTargetExpander::expand(opts);
        auto creds = ZeusCredentialSource::brute_force("a", 1, 1);
        Scheduler scheduler(opts, std::move(targets), std::move(creds));
        ZeusSignalGuard guard(scheduler);
        pause(); // wait for signal; SignalGuard's handler should call _exit()
        _exit(42); // should never be reached if the handler works
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    ASSERT_EQ(::kill(pid, SIGTERM), 0);
    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_NE(WEXITSTATUS(status), 42); // proves the guard's handler ran, not the pause() fallthrough
}