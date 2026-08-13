#include <thread>
#include <boost/asio/ssl.hpp>
#include <gtest/gtest.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "../lib/zeus_engine.hh"


namespace asio = boost::asio;

using asio::ip::tcp;
using namespace std::chrono_literals;
using namespace zeus;



namespace {

/// Generates an in-memory self-signed cert + key pair (RSA 2048, 1 day
/// validity) — no filesystem, no external `openssl` CLI dependency,
/// fully hermetic for CI.
    struct EphemeralCert {
        EVP_PKEY* pkey;
        X509* cert;

        EphemeralCert()
        {
            pkey = EVP_RSA_gen(2048);
            cert = X509_new();
            X509_set_version(cert, 2);
            ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
            X509_gmtime_adj(X509_getm_notBefore(cert), 0);
            X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24);
            X509_set_pubkey(cert, pkey);
            X509_NAME* name = X509_get_subject_name(cert);
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
            X509_set_issuer_name(cert, name);
            X509_sign(cert, pkey, EVP_sha256());
        }
        ~EphemeralCert()
        {
            X509_free(cert);
            EVP_PKEY_free(pkey);
        }
    };

    class TlsEchoServer final
    {
        public:
            TlsEchoServer(): ssl_ctx_(asio::ssl::context::tls_server),acceptor_(io_, tcp::endpoint(tcp::v4(), 0))
            {
                SSL_CTX_use_certificate(ssl_ctx_.native_handle(), cert_.cert);
                SSL_CTX_use_PrivateKey(ssl_ctx_.native_handle(), cert_.pkey);
                port_ = acceptor_.local_endpoint().port();
                thread_ = std::thread([this] { serve_one(); });
            }

            ~TlsEchoServer()
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
            void serve_one()
            {
                asio::ssl::stream<tcp::socket> stream(io_, ssl_ctx_);
                boost::system::error_code ec;
                acceptor_.accept(stream.lowest_layer(), ec);

                if (ec)
                {
                    return;
                }
                stream.handshake(asio::ssl::stream_base::server, ec);

                if (ec)
                {
                    return;
                }
                std::array<char, 64> buf{};
                std::size_t n = stream.read_some(asio::buffer(buf), ec);

                if (!ec)
                {
                    asio::write(stream, asio::buffer(buf, n), ec);
                }
            }
            EphemeralCert cert_;
            asio::io_context io_;
            asio::ssl::context ssl_ctx_;
            tcp::acceptor acceptor_;
            std::uint16_t port_{};
            std::thread thread_;
    };

} // namespace

TEST(ConnectionTls, HandshakeSucceedsAgainstSelfSignedServer)
{
    TlsEchoServer server;
    asio::io_context io;
    Logger log;
    Connection conn(io, log);
    ASSERT_TRUE(conn.connect_tcp(asio::ip::make_address("127.0.0.1"), server.port(), 2s));

    auto result = conn.upgrade_to_tls("localhost");
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(conn.using_tls());
}

TEST(ConnectionTls, SendReceiveWorksOverEncryptedChannel)
{
    TlsEchoServer server;
    asio::io_context io;
    Logger log;
    Connection conn(io, log);
    ASSERT_TRUE(conn.connect_tcp(asio::ip::make_address("127.0.0.1"), server.port(), 2s));
    ASSERT_TRUE(conn.upgrade_to_tls("localhost"));

    std::string msg = "secret-over-tls";
    std::vector<std::byte> out(msg.size());
    std::memcpy(out.data(), msg.data(), msg.size());
    ASSERT_TRUE(conn.send(out));

    std::array<std::byte, 64> in{};
    auto n = conn.receive(in, 2s);
    ASSERT_TRUE(n.has_value());
    EXPECT_EQ(std::string(reinterpret_cast<char*>(in.data()), *n), msg);
}

TEST(ConnectionTls, UpgradeFailsGracefullyWithoutPriorTcpConnect)
{
    // Precondition violated (no TCP layer yet) — must return an error,
    // not crash on a null socket dereference.
    asio::io_context io;
    Logger log;
    Connection conn(io, log);
    auto result = conn.upgrade_to_tls("localhost");
    EXPECT_FALSE(result.has_value());
}
































