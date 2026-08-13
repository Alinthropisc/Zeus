#include <thread>

#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include "../lib/zeus_engine.hh"


namespace asio = boost::asio;

using asio::ip::tcp;
using namespace zeus;
using namespace std::chrono_literals;

namespace
{

/// Local echo server: reads whatever is sent and echoes it back once,
/// then closes. Used to test Connection::send()/receive() round trip.
    class EchoServer final
    {
        public:
            EchoServer() : acceptor_(io_, tcp::endpoint(tcp::v4(), 0))
            {
                port_ = acceptor_.local_endpoint().port();

                thread_ = std::thread([this] {
                    tcp::socket sock(io_);
                    boost::system::error_code ec;
                    acceptor_.accept(sock, ec);
                    if (ec) return;
                    std::array<char, 256> buf{};
                    std::size_t n = sock.read_some(asio::buffer(buf), ec);
                    if (!ec) asio::write(sock, asio::buffer(buf, n), ec);
                });
            }
            ~EchoServer()
            {
                if (thread_.joinable())
                {
                    thread_.join();
                }
            }

            [[nodiscard]]
            std::uint16_t port() const noexcept
            {
                return port_;
            }

        private:
            asio::io_context io_;
            tcp::acceptor acceptor_;
            std::uint16_t port_{};
            std::thread thread_;
    };

/// Server that accepts a connection and then just sits there without
/// ever sending data — used to test the receive() timeout path.
    class SilentServer final
    {
        public:
            SilentServer() : acceptor_(io_, tcp::endpoint(tcp::v4(), 0))
            {
                port_ = acceptor_.local_endpoint().port();
                thread_ = std::thread([this] {
                    tcp::socket sock(io_);
                    boost::system::error_code ec;
                    acceptor_.accept(sock, ec);
                    std::this_thread::sleep_for(500ms); // hold the connection open
                });
            }

            ~SilentServer()
            {
                if (thread_.joinable())
                {
                    thread_.join();
                }
            }

            [[nodiscard]]
            std::uint16_t port() const noexcept
            {
                return port_;
            }

        private:
            asio::io_context io_;
            tcp::acceptor acceptor_;
            std::uint16_t port_{};
            std::thread thread_;
    };

} // namespace

TEST(ZeusConnection, ConnectTcpSucceedsAgainstLocalListener)
{
    EchoServer server;
    boost::asio::io_context io;
    ZeusLogger log;
    ZeusZeusConnection conn(io, log);
    auto result = conn.connect_tcp(asio::ip::make_address("127.0.0.1"), server.port(), 2s);
    EXPECT_TRUE(result.has_value());
}

TEST(ZeusConnection, ConnectTcpFailsFastOnClosedPort)
{
    // Port 1 is reserved (tcpmux) and essentially guaranteed closed on any
    // loopback interface in CI — a stable "nobody is listening" target.
    boost::asio::io_context io;
    ZeusLogger log;
    ZeusConnection conn(io, log);
    auto result = conn.connect_tcp(asio::ip::make_address("127.0.0.1"), 1, 2s);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ConnectError::unreachable);
}

TEST(ZeusConnection, SendThenReceiveRoundTripsThroughEchoServer)
{
    EchoServer server;
    boost::asio::io_context io;
    ZeusLogger log;
    ZeusConnection conn(io, log);
    ASSERT_TRUE(conn.connect_tcp(asio::ip::make_address("127.0.0.1"), server.port(), 2s));
    std::string msg = "hello zeus";
    std::vector<std::byte> out(msg.size());
    std::memcpy(out.data(), msg.data(), msg.size());
    auto sent = conn.send(out);
    ASSERT_TRUE(sent.has_value());
    EXPECT_EQ(*sent, msg.size());
    std::array<std::byte, 64> in{};
    auto received = conn.receive(in, 2s);
    ASSERT_TRUE(received.has_value());
    std::string echoed(reinterpret_cast<char*>(in.data()), *received);
    EXPECT_EQ(echoed, msg);
}

TEST(ZeusConnection, ReceiveTimesOutWhenServerStaysSilent)
{
    SilentServer server;
    boost::asio::io_context io;
    ZeusLogger log;
    ZeusConnection conn(io, log);
    ASSERT_TRUE(conn.connect_tcp(asio::ip::make_address("127.0.0.1"), server.port(), 2s));
    std::array<std::byte, 16> in{};
    auto result = conn.receive(in, 100ms); // much shorter than server's 500ms silence
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ConnectError::timeout);
}

TEST(ZeusConnection, CloseIsIdempotentAndSafeToCallTwice)
{
    EchoServer server;
    boost::asio::io_context io;
    ZeusLogger log;
    ZeusConnection conn(io, log);
    ASSERT_TRUE(conn.connect_tcp(asio::ip::make_address("127.0.0.1"), server.port(), 2s));
    EXPECT_NO_THROW(conn.close());
    EXPECT_NO_THROW(conn.close()); // RAII contract: double-close must not crash
}

TEST(ZeusConnection, DestructorClosesSocketWithoutLeakingOrThrowing)
{
    EchoServer server;
    boost::asio::io_context io;
    ZeusLogger log;
    {
        ZeusConnection conn(io, log);
        ASSERT_TRUE(conn.connect_tcp(asio::ip::make_address("127.0.0.1"), server.port(), 2s));
    } // destructor runs here — this is the actual behaviour under test
    SUCCEED();
}