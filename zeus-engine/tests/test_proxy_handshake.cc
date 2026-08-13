
#include "../lib/zeus_engine.hh"
#include <boost/asio.hpp>
#include <gtest/gtest.h>
#include <thread>

namespace asio = boost::asio;
using asio::ip::tcp;
using namespace zeus;

namespace
{

/// Minimal helper: runs `server_fn(accepted_socket)` once on a background
/// thread, returns the port it's listening on. Server thread is joined
/// in the test body after the client-side call under test completes.
    class FakeServer final
    {
        public:
            template <typename Fn> explicit FakeServer(Fn server_fn)
            {
                acceptor_.emplace(io_, tcp::endpoint(tcp::v4(), 0));
                port_ = acceptor_->local_endpoint().port();
                thread_ = std::thread([this, server_fn = std::move(server_fn)]() mutable {
                    tcp::socket sock(io_);
                    acceptor_->accept(sock);
                    server_fn(sock);
                });
            }
            ~FakeServer()
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
            std::optional<tcp::acceptor> acceptor_;
            std::uint16_t port_{};
            std::thread thread_;
    };

/// Connects a plain client socket to the FakeServer — stands in for the
/// TCP leg that Connection::connect_tcp() would normally have already
/// established before handing the socket to a ProxyHandshake.
    tcp::socket connect_to(asio::io_context& io, std::uint16_t port)
    {
        tcp::socket sock(io);
        sock.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));
        return sock;
    }

} // namespace

TEST(ZeusSocks4Handshake, SendsCorrectRequestAndAcceptsGrantedReply)
{
    FakeServer server([](tcp::socket& sock)
    {
        std::array<std::byte, 9> req{};
        asio::read(sock, asio::buffer(req));
        // Verify wire format: VN=4, CD=1 (connect)
        EXPECT_EQ(std::to_integer<int>(req[0]), 4);
        EXPECT_EQ(std::to_integer<int>(req[1]), 1);
        // Reply: VN=0, CD=90 (request granted)
        std::array<std::byte, 8> reply{std::byte{0}, std::byte{90}};
        asio::write(sock, asio::buffer(reply));
    });
    asio::io_context io;
    auto client = connect_to(io, server.port());
    ZeusSocks4Handshake handshake;
    ZeusProxyConfig cfg{ZeusProxyType::socks4, "127.0.0.1", server.port(), std::nullopt, std::nullopt};
    auto result = handshake.negotiate(client, asio::ip::make_address_v4("1.2.3.4"), 80, cfg);
    ASSERT_TRUE(result.has_value());
}

TEST(ZeusSocks4Handshake, RejectsIpv6TargetAsUnsupported)
{
    asio::io_context io;
    tcp::socket dummy(io); // never actually connected; negotiate() must
    ZeusSocks4Handshake handshake;
    ZeusProxyConfig cfg{ZeusProxyType::socks4, "127.0.0.1", 1080, std::nullopt, std::nullopt};
    auto result = handshake.negotiate(dummy, asio::ip::make_address_v6("::1"), 80, cfg);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ZeusProxyError::unsupported);
}

TEST(ZeusSocks4Handshake, PropagatesRejectionFromServer)
{
    FakeServer server([](tcp::socket& sock)
    {
        std::array<std::byte, 9> req{};
        asio::read(sock, asio::buffer(req));
        std::array<std::byte, 8> reply{std::byte{0}, std::byte{91}}; // 91 = rejected
        asio::write(sock, asio::buffer(reply));
    });
    asio::io_context io;
    auto client = connect_to(io, server.port());
    ZeusSocks4Handshake handshake;
    ZeusProxyConfig cfg{ZeusProxyType::socks4, "127.0.0.1", server.port(), std::nullopt, std::nullopt};
    auto result = handshake.negotiate(client, asio::ip::make_address_v4("1.2.3.4"), 80, cfg);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ZeusProxyError::negotiation_failed);
}

TEST(ZeusSocks5Handshake, NoAuthFlowSendsGreetingThenConnectRequest)
{
    FakeServer server([](tcp::socket& sock)
    {
        std::array<std::byte, 3> greet{};
        asio::read(sock, asio::buffer(greet));
        EXPECT_EQ(std::to_integer<int>(greet[0]), 5); // SOCKS version
        EXPECT_EQ(std::to_integer<int>(greet[2]), 0); // NOAUTH requested
        std::array<std::byte, 2> greet_reply{std::byte{5}, std::byte{0}};
        asio::write(sock, asio::buffer(greet_reply));
        std::array<std::byte, 10> connect_req{};
        asio::read(sock, asio::buffer(connect_req));
        EXPECT_EQ(std::to_integer<int>(connect_req[3]), 1); // ATYP = IPv4
        std::array<std::byte, 10> connect_reply{std::byte{5}, std::byte{0}};
        asio::write(sock, asio::buffer(connect_reply));
    });
    asio::io_context io;
    auto client = connect_to(io, server.port());
    ZeusSocks5Handshake handshake;
    ZeusProxyConfig cfg{ZeusProxyType::socks5, "127.0.0.1", server.port(), std::nullopt, std::nullopt};
    auto result = handshake.negotiate(client, asio::ip::make_address_v4("5.6.7.8"), 443, cfg);
    ASSERT_TRUE(result.has_value());
}

TEST(ZeusSocks5Handshake, AuthFailureIsReportedDistinctlyFromNegotiationFailure)
{
    FakeServer server([](tcp::socket& sock)
    {
        std::array<std::byte, 3> greet{};
        asio::read(sock, asio::buffer(greet));
        EXPECT_EQ(std::to_integer<int>(greet[2]), 2); // PASSAUTH requested
        std::array<std::byte, 2> greet_reply{std::byte{5}, std::byte{2}};
        asio::write(sock, asio::buffer(greet_reply));
        std::vector<std::byte> auth_req(1024);
        std::size_t n = sock.read_some(asio::buffer(auth_req));
        (void)n;
        std::array<std::byte, 2> auth_reply{std::byte{1}, std::byte{1}}; // status != 0 = failure
        asio::write(sock, asio::buffer(auth_reply));
    });
    asio::io_context io;
    auto client = connect_to(io, server.port());
    ZeusSocks5Handshake handshake;
    ZeusProxyConfig cfg{ZeusProxyType::socks5, "127.0.0.1", server.port(), std::string{"user"}, std::string{"pass"}};
    auto result = handshake.negotiate(client, asio::ip::make_address_v4("5.6.7.8"), 443, cfg);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ZeusProxyError::auth_failed);
}

TEST(ZeusHttpConnectHandshake, SendsProxyAuthorizationHeaderWhenCredsProvided)
{
    FakeServer server([](tcp::socket& sock)
    {
        asio::streambuf buf;
        asio::read_until(sock, buf, "\r\n\r\n");
        std::istream is(&buf);
        std::string request((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
        EXPECT_NE(request.find("Proxy-Authorization: Basic dXNlcjpwYXNz"), std::string::npos);
        std::string reply = "HTTP/1.0 200 Connection established\r\n\r\n";
        asio::write(sock, asio::buffer(reply));
    });
    asio::io_context io;
    auto client = connect_to(io, server.port());
    ZeusHttpConnectHandshake handshake;
    ZeusProxyConfig cfg{ZeusProxyType::http_connect, "127.0.0.1", server.port(), std::string{"dXNlcjpwYXNz"}, std::nullopt};
    auto result = handshake.negotiate(client, asio::ip::make_address_v4("9.9.9.9"), 443, cfg);
    ASSERT_TRUE(result.has_value());
}

TEST(ZeusHttpConnectHandshake, NonTwoXXStatusIsNegotiationFailure)
{
    FakeServer server([](tcp::socket& sock)
    {
        asio::streambuf buf;
        asio::read_until(sock, buf, "\r\n\r\n");
        std::string reply = "HTTP/1.0 407 Proxy Authentication Required\r\n\r\n";
        asio::write(sock, asio::buffer(reply));
    });
    asio::io_context io;
    auto client = connect_to(io, server.port());
    ZeusHttpConnectHandshake handshake;
    ZeusProxyConfig cfg{ZeusProxyType::http_connect, "127.0.0.1", server.port(), std::nullopt, std::nullopt};
    auto result = handshake.negotiate(client, asio::ip::make_address_v4("9.9.9.9"), 443, cfg);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ZeusProxyError::negotiation_failed);
}

TEST(ZeusProxyHandshakeFactory, CreatesCorrectStrategyPerType)
{
    EXPECT_NE(dynamic_cast<ZeusSocks4Handshake*>(ZeusProxyHandshakeFactory::create(ZeusProxyType::socks4).get()), nullptr);
    EXPECT_NE(dynamic_cast<ZeusSocks5Handshake*>(ZeusProxyHandshakeFactory::create(ZeusProxyType::socks5).get()), nullptr);
    EXPECT_NE(dynamic_cast<ZeusHttpConnectHandshake*>(ZeusProxyHandshakeFactory::create(ZeusProxyType::http_connect).get()), nullptr);
    EXPECT_EQ(ZeusProxyHandshakeFactory::create(ZeusProxyType::none), nullptr);
}