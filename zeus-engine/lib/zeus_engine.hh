#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <expected>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <random>
#include <vector>

#include <unistd.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "../../zeus-core/lib/zeus.hh"
#include "../../zeus-core/lib/zeus_types.hh"
#include "../../zeus-core/lib/zeus_contract.hh"


namespace zeus
{
    namespace asio = boost::asio;
    using asio::ip::tcp;
    using asio::ip::udp;

//    enum class ZeusLogLevel {
//        quiet,
//        normal,
//        verbose,
//        debug,
//    };

    class ZeusLogger final
    {
        public:
            explicit ZeusLogger(ZeusLogLevel level = ZeusLogLevel::normal) noexcept : level_(level)
            {

            }

            void set_level(ZeusLogLevel l) noexcept
            {
                level_ = l;
            }

            template<typename... A> void debug(std::format_string<A...> fmt, A&&... a) const
            {
                if (this->is_debug())
                {
                    emit(stdout, "[ ETA ]: DEBUG ", fmt, std::forward<A>(a)...);
                }
            }

            template<typename... A> void verbose(std::format_string<A...> fmt, A&&... a) const
            {
                if (this->is_verbose())
                {
                    emit(stderr, "[ ETA ]: VERBOSE ", fmt, std::forward<A>(a)...);
                }
            }

            template<typename... A> void error(std::format_string<A...> fmt, A&&... a) const
            {
                emit(stderr, "[ ETA ]: ERROR ", fmt, std::forward<A>(a)...);
            }

            static void hex_dump(std::span<const std::byte> data, std::string_view title, std::FILE *out = stdout);

        private:
            ZeusLogLevel level_;

            template<typename... A> void emit(std::FILE *f, std::string_view prefix, std::format_string<A...> fmt, A&... a) const
            {
                std::fputs(std::string(prefix).c_str(), f);
                std::fputs(std::format(fmt, std::forward<A>(a)...).c_str(), f);
                std::fputc('\n', f);
            }
    };

//    enum class ZeusProxyType {
//        none,
//        http_connect,
//        socks4,
//        socks5,
//    };
//
//    struct ZeusProxyConfig {
//        ZeusProxyType type{ZeusProxyType::none};
//        std::string host;
//        std::uint16_t port{};
//        std::optional<std::string> login;
//        std::optional<std::string> password;
//    };

//    enum class ZeusProxyError {
//        negotiation_failed,
//        auth_failed,
//        io_error,
//        unsupported,
//    };

    class ZeusProxyHandshake
    {
        public:
            virtual ~ZeusProxyHandshake() = default;

            [[nodiscard]]
            virtual std::expected<void, ZeusProxyError> negotiate(tcp::socket& sock, const asio::ip::address& target,std::uint16_t target_port, const ZeusProxyConfig& cfg) const = 0;
    };

    class ZeusSocks4Handshake final : public ZeusProxyHandshake
    {
        public:
            [[nodiscard]]
            std::expected<void, ZeusProxyError> negotiate(tcp::socket&, const asio::ip::address&, std::uint16_t, const ZeusProxyConfig&) const override;
    };

    class ZeusSocks5Handshake final : public ZeusProxyHandshake
    {
        public:
            [[nodiscard]]
            std::expected<void, ZeusProxyError> negotiate(tcp::socket&, const asio::ip::address&, std::uint16_t, const ZeusProxyConfig&) const override;
    };

    class ZeusHttpConnectHandshake final : public ZeusProxyHandshake
    {
        public:
            [[nodiscard]]
            std::expected<void, ZeusProxyError> negotiate(tcp::socket&, const asio::ip::address&, std::uint16_t, const ZeusProxyConfig&) const override;
    };

    class ZeusProxyHandshakeFactory final
    {
        public:
            [[nodiscard]]
            static std::unique_ptr<ZeusProxyHandshake> create(ZeusProxyType type);
    };

    class ZeusProxyPool final
    {
        public:
            void add(ZeusProxyConfig cfg)
            {
                proxies_.push_back(std::move(cfg));
            }

            [[nodiscard]]
            bool empty() const noexcept
            {
                return proxies_.empty();
            }

            // [[nodiscard]]
            // const ZeusProxyConfig& pick_random() const;

            [[nodiscard]]
            const ZeusProxyConfig& pick_random() const
            {
                ZEUS_EXPECTS(!proxies_.empty());
                static thread_local std::mt19937 rng{std::random_device{}()};
                std::uniform_int_distribution<std::size_t> dist(0, proxies_.size() - 1);
                return proxies_[dist(rng)];
            }

        private:
            std::vector<ZeusProxyConfig> proxies_;
    };

//    enum class ZeusConnectError {
//        timeout,
//        unreachable,
//        proxy_error,
//        tls_error,
//        io_error,
//        need_root,
//    };

    [[nodiscard]]
    constexpr std::string_view to_string(ZeusConnectError e) noexcept
    {
        switch (e)
        {
            case ZeusConnectError::timeout:
                return "[ ETA ]: connection timed out";
                break;
            case ZeusConnectError::unreachable:
                return "[ ETA ]: host unreachable";
                break;
            case ZeusConnectError::proxy_error:
                return "[ ETA ]: proxy negotiation failed";
                break;
            case ZeusConnectError::tls_error:
                return "[ ETA ]: TLS handshake failed";
                break;
            case ZeusConnectError::io_error:
                return "[ ETA ]: I/O error";
                break;
            case ZeusConnectError::need_root:
                return "[ ETA ]: root privileges required for source port";
                break;
        }
        return "[ ETA ]: unknown";
    }

    class ZeusConnection final
    {
        public:
            explicit ZeusConnection(asio::io_context& io, ZeusLogger& log) : io_{io}, log_{log}
            {

            }

            ~ZeusConnection()
            {
                close();
            }
            ZeusConnection(const ZeusConnection&) = delete;
            ZeusConnection& operator=(const ZeusConnection&) = delete;
            ZeusConnection(ZeusConnection&&) noexcept = default;
            ZeusConnection& operator=(ZeusConnection&&) noexcept = default;

            [[nodiscard]]
            std::expected<void, ZeusConnectError>connect_tcp(const asio::ip::address& host, std::uint16_t port,std::chrono::seconds timeout,const ZeusProxyPool* proxies = nullptr,std::optional<std::uint16_t> source_port = std::nullopt);

            [[nodiscard]]
            std::expected<void, ZeusConnectError> connect_udp(const asio::ip::address& host, std::uint16_t port);

            [[nodiscard]]
            std::expected<void, ZeusConnectError> upgrade_to_tls(std::string_view sni_hostname);

            [[nodiscard]]
            std::expected<std::size_t, ZeusConnectError> send(std::span<const std::byte> data);

            [[nodiscard]]
            std::expected<std::size_t, ZeusConnectError> receive(std::span<std::byte> buffer, std::chrono::milliseconds timeout);

            /// Аналог hydra_receive_line(): читает, пока не '\n' либо таймаут/EOF.
            [[nodiscard]]
            std::string receive_line(std::chrono::milliseconds timeout);

            [[nodiscard]]
            bool data_ready(std::chrono::milliseconds timeout) const;

            [[nodiscard]]
            bool using_tls() const noexcept
            {
                return static_cast<bool>(tls_stream_);
            }

            void close() noexcept;

        private:
            asio::io_context& io_;
            ZeusLogger& log_;
            std::optional<tcp::socket> tcp_socket_;
            std::optional<udp::socket> udp_socket_;
            std::optional<asio::ssl::context> tls_ctx_;
            std::unique_ptr<asio::ssl::stream<tcp::socket&>> tls_stream_;
    };

//    struct ZeusFinding {
//        std::uint16_t port{};
//        std::string service, host;
//        std::optional<std::string> login, password, message;
//    };

    class ZeusReportSink
    {
        public:
            virtual ~ZeusReportSink() = default;
            virtual void on_found(const ZeusFinding&) = 0;
    };

    class ZeusFileReportSink final : public ZeusReportSink
    {
        public:
            explicit ZeusFileReportSink(std::FILE* fp, bool colored = true) : fp_{fp}, colored_{colored} {}
            void on_found(const ZeusFinding&) override;
        private:
            std::FILE* fp_;
            bool colored_;
    };

    class ZeusCompositeReportSink final : public ZeusReportSink
    {
        public:
            void add(std::shared_ptr<ZeusReportSink> sink)
            {
                sinks_.push_back(std::move(sink));
            }

            void on_found(const ZeusFinding& f) override
            {
                for (auto& s : sinks_) s->on_found(f);
            }

        private:
            std::vector<std::shared_ptr<ZeusReportSink>> sinks_;
    };

//    struct ZeusCredential {
//        std::string login, password;
//    };

    class ZeusIpcChannel final
    {
        public:
            explicit ZeusIpcChannel(int fd) noexcept : fd_{fd} {}
            ~ZeusIpcChannel() { if (fd_ >= 0) ::close(fd_); }
            ZeusIpcChannel(const ZeusIpcChannel&) = delete;
            ZeusIpcChannel& operator=(const ZeusIpcChannel&) = delete;
            ZeusIpcChannel(ZeusIpcChannel&& o) noexcept : fd_{o.fd_}
            {
                o.fd_ = -1;
            }

            [[nodiscard]]
            std::optional<ZeusCredential> next_pair();

            void report_done();
            void report_found(std::string_view login);
            void report_skip(std::string_view login);

        private:
            int fd_;
            static constexpr std::array<std::byte, 5> kExit{std::byte{0x00}, std::byte{0xff}, std::byte{0x00}, std::byte{0xff}, std::byte{0x00}};
    };

    class ZeusEngine final
    {
        public:
//            struct ZeusOptions {
//                ZeusLogLevel log_level{ZeusLogLevel::normal};
//                std::chrono::seconds connect_timeout{30};
//                std::uint16_t target_port{};
//                bool ssl{false};
//                std::optional<std::uint16_t> source_port;
//                int connect_retries{1};
//                bool do_retry{true};       // было: int32_t do_retry (hydra-mod.c)
//                bool old_ssl{false};       // было: int32_t old_ssl
//                bool colored_output{true}; // было: uint32_t colored_output
//                bool quiet{false};
//            };

            ZeusEngine(types::ZeusConnectOptions opts, ZeusIpcChannel ipc, ZeusCompositeReportSink reporter): options_{opts}, logger_{opts.log_level}, ipc_{std::move(ipc)},reporter_{std::move(reporter)}
            {

            }

            [[nodiscard]]
            ZeusLogger& logger() noexcept
            {
                return logger_;
            }

            [[nodiscard]]
            const types::ZeusConnectOptions& options() const noexcept
            {
                return options_;
            }

            [[nodiscard]]
            ZeusProxyPool& proxies() noexcept
            {
                return proxies_;
            }

            [[nodiscard]]
            ZeusIpcChannel& ipc() noexcept
            {
                return ipc_;
            }

            [[nodiscard]]
            ZeusCompositeReportSink& reporter() noexcept
            {
                return reporter_;
            }

            [[nodiscard]]
            std::unique_ptr<ZeusConnection> make_connection()
            {
                return std::make_unique<ZeusConnection>(io_, logger_);
            }

            void report_success(std::string service, std::string host,std::optional<std::string> login,std::optional<std::string> password,std::optional<std::string> message = std::nullopt)
            {
                reporter_.on_found(ZeusFinding{options_.target_port, std::move(service), std::move(host),std::move(login), std::move(password), std::move(message)});
            }

            [[noreturn]]
            void exit_worker(ZeusExitCode code)
            {
                throw ZeusEngineExit{code};
            }

            void run(ZeusServices& services)
            {
                services.init(*this);

                while (true)
                {
                    auto cred = ipc_.next_pair();

                    if (!cred)
                    {
                        break;
                    }
                    try {
                        services.try_login(*this, cred->login, cred->password);
                        ipc_.report_done();
                    } catch (const ZeusEngineExit& e) {
                        if (e.code() == ZeusExitCode::normal)
                        {
                            ipc_.report_done();
                        }
                        throw;
                    }
                }
            }

        private:
            types::ZeusConnectOptions options_;
            ZeusLogger logger_;
            asio::io_context io_;
            ZeusProxyPool proxies_;
            ZeusIpcChannel ipc_;
            ZeusCompositeReportSink reporter_;
    };
}



























