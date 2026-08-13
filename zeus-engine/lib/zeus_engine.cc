#include <iostream>
#include <cctype>
#include <random>
#include <format>
#include <unistd.h>

#include <boost/asio/connect.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/write.hpp>

#include "zeus_engine.hh"

namespace zeus
{
    void ZeusLogger::hex_dump(std::span<const std::byte> data, std::string_view title, std::FILE *out)
    {
        if (!title.empty())
        {
            std::fprintf(out, "%.*s (%zu bytes):\n", static_cast<int>(title.size()), title.data(), data.size());
        }
        constexpr std::size_t kRow = 16;

        for (std::size_t i = 0; i < data.size(); i += kRow)
        {
            std::fprintf(out, "%04zx: ", i);
            std::size_t row_len = std::min(kRow, data.size() - i);

            for (std::size_t j = 0; j < row_len; ++j)
            {
                std::fprintf(out, "%02x%s", std::to_integer<unsigned>(data[i + j]), (j % 2) ? " " : "");
            }
            std::fputs(" [ ", out);

            for (std::size_t j = 0; j < row_len; ++j)
            {
                auto c = std::to_integer<unsigned char>(data[i + j]);
                std::fputc(std::isprint(c) ? static_cast<char>(c) : '.', out);
            }
            std::fputs(" ]\n", out);
        }
    }



    std::unique_ptr<ZeusProxyHandshake> ZeusProxyHandshakeFactory::create(ZeusProxyType type)
    {
        switch (type)
        {
            case ZeusProxyType::socks4:
                return std::make_unique<ZeusSocks4Handshake>();
                break;
            case ZeusProxyType::socks5:
                return std::make_unique<ZeusSocks5Handshake>();
                break;
            case ZeusProxyType::http_connect:
                return std::make_unique<ZeusHttpConnectHandshake>();
                break;
            default:
                return nullptr;
        }
    }

    const ZeusProxyConfig &ZeusProxyPool::pick_random() const
    {
        static thread_local std::mt19937_64 rng{std::random_device()()};
        std::uniform_int_distribution<std::size_t> dist(0, proxies_.size() - 1);
        return proxies_[dist(rng)];
    }

    std::expected<void, ZeusProxyError> ZeusSocks4Handshake::negotiate(tcp::socket &socket, const asio::ip::address &target,std::uint16_t port, const ZeusProxyConfig &) const
    {
        if (!target.is_v4())
        {
            return std::unexpected(ZeusProxyError::unsupported); // SOCKS4 = Only IPv4
        }
        std::array<std::byte, 9> req{};
        req[0] = std::byte{4}; // connect
        req[1] = std::byte{1}; // connect
        auto p = target.to_v4().to_bytes();
        std::uint16_t nport = htons(port);
        std::memcpy(&req[2], &nport, 2);
        std::memcpy(&req[4], p.data(), 4);
        req[8] = std::byte{0};
        boost::system::error_code ec;
        asio::write(socket, asio::buffer(req), ec);

        if (ec)
        {
            return std::unexpected(ZeusProxyError::io_error);
        }
        std::array<std::byte, 8> reply{};
        asio::read(socket, asio::buffer(reply), ec);

        if (ec)
        {
            return std::unexpected(ZeusProxyError::io_error);
        }

        if (std::to_integer<int>(reply[1]) != 90)
        {
            return std::unexpected(ZeusProxyError::negotiation_failed);
        }
        return {};
    }


    std::expected<void, ZeusProxyError> ZeusSocks5Handshake::negotiate(tcp::socket& sock, const asio::ip::address& target,std::uint16_t port, const ZeusProxyConfig& cfg) const
    {
        boost::system::error_code ec;
        bool need_auth = cfg.login.has_value();
        std::array<std::byte, 3> greet{std::byte{5}, std::byte{1},need_auth ? std::byte{2} : std::byte{0}};
        asio::write(sock, asio::buffer(greet), ec);
        std::array<std::byte, 2> gresp{};
        asio::read(sock, asio::buffer(gresp), ec);

        if (ec || std::to_integer<int>(gresp[1]) == 0xff)
        {
            return std::unexpected(ZeusProxyError::negotiation_failed);
        }

        if (need_auth)
        {
            std::string user = *cfg.login, pass = cfg.password.value_or("");
            std::vector<std::byte> auth;
            auth.push_back(std::byte{1});
            auth.push_back(std::byte(user.size()));
            for (char c : user) auth.push_back(std::byte(c));
            auth.push_back(std::byte(pass.size()));
            for (char c : pass) auth.push_back(std::byte(c));
            asio::write(sock, asio::buffer(auth), ec);
            std::array<std::byte, 2> aresp{};
            asio::read(sock, asio::buffer(aresp), ec);

            if (ec || std::to_integer<int>(aresp[1]) != 0)
            {
                return std::unexpected(ZeusProxyError::auth_failed);
            }
        }
        std::vector<std::byte> req{std::byte{5}, std::byte{1}, std::byte{0}};

        if (target.is_v6())
        {
            req.push_back(std::byte{4});
            auto b = target.to_v6().to_bytes();
            for (auto x : b) req.push_back(std::byte(x));
        }
        else
        {
            req.push_back(std::byte{1});
            auto b = target.to_v4().to_bytes();
            for (auto x : b) req.push_back(std::byte(x));
        }
        std::uint16_t nport = htons(port);
        req.push_back(std::byte(nport & 0xff));
        req.push_back(std::byte(nport >> 8));
        asio::write(sock, asio::buffer(req), ec);
        std::array<std::byte, 10> resp{};
        asio::read(sock, asio::buffer(resp), ec);

        if (ec || std::to_integer<int>(resp[1]) != 0)
        {
            return std::unexpected(ZeusProxyError::negotiation_failed);
        }
        return {};
    }

    std::expected<void, ZeusProxyError> ZeusHttpConnectHandshake::negotiate(tcp::socket& sock, const asio::ip::address& target,std::uint16_t port, const ZeusProxyConfig& cfg) const
    {
        std::string req = std::format("CONNECT {}:{} HTTP/1.0\r\n", target.to_string(), port);

        if (cfg.login)
        {
            req += std::format("Proxy-Authorization: Basic {}\r\n", *cfg.login);
        }
        req += "\r\n";
        boost::system::error_code ec;
        asio::write(sock, asio::buffer(req), ec);

        if (ec)
        {
            return std::unexpected(ZeusProxyError::io_error);
        }
        asio::streambuf buf;
        asio::read_until(sock, buf, "\r\n", ec);

        if (ec)
        {
            return std::unexpected(ZeusProxyError::io_error);
        }
        std::istream is(&buf);
        std::string status_line;
        std::getline(is, status_line);
        if (status_line.find("HTTP/") != 0 || status_line.find(" 2") == std::string::npos)
        {
            return std::unexpected(ZeusProxyError::negotiation_failed);
        }
        return {};
    }

    std::expected<void, ZeusConnectError> ZeusConnection::connect_tcp(const asio::ip::address& host, std::uint16_t port,std::chrono::seconds timeout, const ZeusProxyPool* proxies,std::optional<std::uint16_t> source_port)
    {
        tcp_socket_.emplace(io_);
        boost::system::error_code ec;

        if (source_port)
        {
            tcp_socket_->open(host.is_v6() ? tcp::v6() : tcp::v4(), ec);
            tcp_socket_->set_option(asio::socket_base::reuse_address(true));
            tcp_socket_->bind(tcp::endpoint(host.is_v6() ? tcp::v6() : tcp::v4(), *source_port), ec);
            if (ec == boost::asio::error::access_denied) return std::unexpected(ZeusConnectError::need_root);
        }
        asio::ip::address connect_target = host;
        std::uint16_t connect_port = port;
        bool via_proxy = proxies && !proxies->empty();
        const ZeusProxyConfig* proxy = nullptr;

        if (via_proxy)
        {
            proxy = &proxies->pick_random();
            connect_target = asio::ip::make_address(proxy->host, ec);
            connect_port = proxy->port;
        }
        // Таймаут через steady_timer вместо SIGALRM/alarm().
        asio::steady_timer timer(io_);
        timer.expires_after(timeout);
        bool timed_out = false;

        timer.async_wait([&](const boost::system::error_code& tec) {
            if (!tec)
            {
                timed_out = true; tcp_socket_->cancel();
            }
        });

        tcp_socket_->async_connect(tcp::endpoint(connect_target, connect_port),[&](const boost::system::error_code& cec) { ec = cec; });
        io_.restart();
        io_.run();
        timer.cancel();

        if (timed_out)
        {
            return std::unexpected(ZeusConnectError::timeout);
        }

        if (ec)
        {
            return std::unexpected(ZeusConnectError::unreachable);
        }

        if (via_proxy && proxy->type != ZeusProxyType::none)
        {
            auto handshake = ZeusProxyHandshakeFactory::create(proxy->type);
            auto res = handshake->negotiate(*tcp_socket_, host, port, *proxy);

            if (!res)
            {
                close();
                return std::unexpected(ZeusConnectError::proxy_error);
            }
        }
        return {};
    }

    std::expected<void, ZeusConnectError> ZeusConnection::connect_udp(const asio::ip::address& host, std::uint16_t port)
    {
        udp_socket_.emplace(io_, host.is_v6() ? udp::v6() : udp::v4());
        boost::system::error_code ec;
        udp_socket_->connect(udp::endpoint(host, port), ec);

        if (ec)
        {
            return std::unexpected(ZeusConnectError::unreachable);
        }
        return {};
    }

    std::expected<void, ZeusConnectError> ZeusConnection::upgrade_to_tls(std::string_view sni)
    {
        if (!tcp_socket_)
        {
            return std::unexpected(ZeusConnectError::io_error);
        }
        tls_ctx_.emplace(asio::ssl::context::tls_client);
        tls_ctx_->set_verify_mode(asio::ssl::verify_none); // как и оригинал: без верификации CN
        tls_stream_ = std::make_unique<asio::ssl::stream<tcp::socket&>>(*tcp_socket_, *tls_ctx_);
        SSL_set_tlsext_host_name(tls_stream_->native_handle(), std::string{sni}.c_str());
        boost::system::error_code ec;
        tls_stream_->handshake(asio::ssl::stream_base::client, ec);

        if (ec)
        {
            tls_stream_.reset();
            return std::unexpected(ZeusConnectError::tls_error);
        }
        return {};
    }

    std::expected<std::size_t, ZeusConnectError> ZeusConnection::send(std::span<const std::byte> data)
    {
        boost::system::error_code ec;
        std::size_t n = tls_stream_ ? asio::write(*tls_stream_, asio::buffer(data.data(), data.size()), ec) : asio::write(*tcp_socket_,  asio::buffer(data.data(), data.size()), ec);

        if (ec)
        {
            return std::unexpected(ZeusConnectError::io_error);
        }
        return n;
    }

    std::expected<std::size_t, ZeusConnectError> ZeusConnection::receive(std::span<std::byte> buffer, std::chrono::milliseconds timeout)
    {
        boost::system::error_code ec;
        bool timed_out = false;
        asio::steady_timer timer(io_);
        timer.expires_after(timeout);
        std::size_t n = 0;

        auto on_read = [&](const boost::system::error_code& rec, std::size_t bytes)
        {
            ec = rec; n = bytes;
        };

        if (tls_stream_)
        {
            tls_stream_->async_read_some(asio::buffer(buffer.data(), buffer.size()), on_read);
        }
        else
        {
            tcp_socket_->async_read_some(asio::buffer(buffer.data(), buffer.size()), on_read);
        }

        timer.async_wait([&](const boost::system::error_code& tec) {
            if (!tec)
            {
                timed_out = true;
                tcp_socket_->cancel();
            }
        });
        io_.restart();
        io_.run();
        timer.cancel();

        if (timed_out)
        {
            return std::unexpected(ZeusConnectError::timeout);
        }

        if (ec)
        {
            return std::unexpected(ZeusConnectError::io_error);
        }
        return n;
    }

    std::string ZeusConnection::receive_line(std::chrono::milliseconds timeout)
    {
        std::string result;
        std::array<std::byte, 1024> chunk{};

        while (data_ready(timeout))
        {
            auto res = receive(chunk, timeout);

            if (!res || *res == 0)
            {
                break;
            }

            for (std::size_t i = 0; i < *res; ++i)
            {
                result.push_back(chunk[i] == std::byte{0} ? ' ' : static_cast<char>(chunk[i]));
            }

            if (!result.empty() && result.back() == '\n')
            {
                break;
            }
        }
        return result;
    }

    bool ZeusConnection::data_ready(std::chrono::milliseconds timeout) const
    {
        if (!tcp_socket_)
        {
            return false;
        }
        return tcp_socket_->available() > 0; // упрощённая неблокирующая проверка
    }

    void ZeusConnection::close() noexcept
    {
        boost::system::error_code ec;

        if (tls_stream_)
        {
            tls_stream_->shutdown(ec);
            tls_stream_.reset();
        }

        if (tcp_socket_ && tcp_socket_->is_open())
        {
            tcp_socket_->close(ec);
        }

        if (udp_socket_ && udp_socket_->is_open())
        {
            udp_socket_->close(ec);
        }
    }

    void ZeusFileReportSink::on_found(const ZeusFinding& f)
    {
        std::string line = std::format("[{}][{}] host: {}", f.port, f.service, f.host);

        if (f.login)
        {
            line += std::format(" login: {}", *f.login);
        }

        if (f.password)
        {
            line += std::format(" password: {}", *f.password);
        }

        if (f.message)
        {
            line += std::format(" [{}]", *f.message);
        }
        std::fprintf(fp_, "%s\n", line.c_str());
        std::fflush(fp_);
    }

    std::optional<ZeusCredential> ZeusIpcChannel::next_pair()
    {
        std::array<std::byte, 260> buf{};
        ssize_t got = ::read(fd_, buf.data(), buf.size() - 1);

        if (got <= 0)
        {
            return std::nullopt;
        }

        if (static_cast<std::size_t>(got) == kExit.size() && std::equal(kExit.begin(), kExit.end(), buf.begin()))
        {
            return std::nullopt;
        }
        auto* raw = reinterpret_cast<char*>(buf.data());
        std::string login(raw);
        std::string password(raw + login.size() + 1);
        return ZeusCredential{std::move(login), std::move(password)};
    }

    void ZeusIpcChannel::report_done()
    {
        char c = 'N';
        (void)!::write(fd_, &c, 1);
    }

    void ZeusIpcChannel::report_found(std::string_view login)
    {
        char c = 'F';
        (void)!::write(fd_, &c, 1);
        (void)!::write(fd_, login.data(), login.size() + 1);
    }

    void ZeusIpcChannel::report_skip(std::string_view login)
    {
        char c = 'f';
        (void)!::write(fd_, &c, 1);
        (void)!::write(fd_, login.data(), login.size() + 1);
    }
}


















