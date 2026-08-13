#include <unistd.h>

#include <gtest/gtest.h>
#include <sys/socket.h>

#include "../lib/zeus_engine.hh"


using namespace zeus;

namespace
{
/// Creates a connected pair of Unix-domain stream sockets and wraps one
/// end in an IpcChannel; the other end (`peer_fd`) is driven directly by
/// the test to simulate the "parent" (Scheduler) side of the protocol.
    struct IpcFixture {
        int peer_fd;
        ZeusIpcChannel channel;

        IpcFixture() : peer_fd{make_pair()}, channel{child_fd_}
        {

        }

    private:
        int child_fd_;

        int make_pair()
        {
            int fds[2];
            int rc = ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
            EXPECT_EQ(rc, 0);
            child_fd_ = fds[0];
            return fds[1];
        }
    };
} // namespace

TEST(ZeusIpcChannel, NextPairParsesLoginAndPasswordSeparatedByNul)
{
    IpcFixture fx;
    std::string wire = std::string("admin") + '\0' + "s3cr3t" + '\0';
    ::write(fx.peer_fd, wire.data(), wire.size());
    auto cred = fx.channel.next_pair();
    ASSERT_TRUE(cred.has_value());
    EXPECT_EQ(cred->login, "admin");
    EXPECT_EQ(cred->password, "s3cr3t");
}

TEST(ZeusIpcChannel, ExitSentinelYieldsNullopt)
{
    IpcFixture fx;
    static constexpr std::array<char, 5> exit_sentinel{char(0x00), char(0xff), char(0x00), char(0xff), char(0x00)};
    ::write(fx.peer_fd, exit_sentinel.data(), exit_sentinel.size());
    auto cred = fx.channel.next_pair();
    EXPECT_FALSE(cred.has_value());
}

TEST(ZeusIpcChannel, PeerCloseYieldsNullopt)
{
    IpcFixture fx;
    ::close(fx.peer_fd);

    auto cred = fx.channel.next_pair();
    EXPECT_FALSE(cred.has_value()); // read() returns 0 -> treated like exit
}

TEST(ZeusIpcChannel, ReportDoneWritesLiteralN)
{
    IpcFixture fx;
    fx.channel.report_done();
    char c = 0;
    ::read(fx.peer_fd, &c, 1);
    EXPECT_EQ(c, 'N');
}

TEST(ZeusIpcChannel, ReportFoundWritesFThenLoginWithTrailingNul)
{
    IpcFixture fx;
    fx.channel.report_found("root");

    char status = 0;
    ::read(fx.peer_fd, &status, 1);
    EXPECT_EQ(status, 'F');

    char buf[16] = {};
    ssize_t n = ::read(fx.peer_fd, buf, sizeof(buf));
    ASSERT_GT(n, 0);
    EXPECT_STREQ(buf, "root");
    EXPECT_EQ(buf[4], '\0'); // trailing NUL was actually transmitted
}

TEST(ZeusIpcChannel, ReportSkipWritesLowercaseF)
{
    IpcFixture fx;
    fx.channel.report_skip("guest");
    char status = 0;
    ::read(fx.peer_fd, &status, 1);
    EXPECT_EQ(status, 'f');
}