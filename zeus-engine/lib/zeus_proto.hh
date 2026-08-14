#pragma once

#include <span>
#include <string>
#include <vector>

#include "../../zeus-core/lib/zeus_contract.hh"
#include "../../zeus-core/lib/zeus_types.hh"
#include "zeus_net.hh"
#include "zeus_engine.hh"

namespace zeus::proto
{
//    enum class ZeusAuthResult {
//        success,        // credentials accepted
//        failure,        // credentials rejected (this pair is simply wrong)
//        retry,          // transient issue (rate limit, busy) — requeue the pair
//        protocol_error, // service spoke something we don't understand — abort target
//    };

    class ZeusPacketCodec
    {
        public:
            virtual ~ZeusPacketCodec() = default;

            [[nodiscard]]
            virtual std::vector<std::byte> encode(std::string_view payload) const = 0;
            /// @pre  !raw.empty()
            /// @post returns a complete decoded frame, or nullopt if more bytes are needed
            [[nodiscard]]
            virtual std::optional<std::string> decode(std::span<const std::byte> raw) const = 0;
    };

    class ZeusLineProtocolCodec final : public ZeusPacketCodec
    {
        public:
            [[nodiscard]]
            std::vector<std::byte> encode(std::string_view payload) const override
            {
                std::vector<std::byte> out(payload.size() + 2);
                std::memcpy(out.data(), payload.data(), payload.size());
                out[payload.size()]     = std::byte{'\r'};
                out[payload.size() + 1] = std::byte{'\n'};
                return out;
            }

            [[nodiscard]]
            std::optional<std::string> decode(std::span<const std::byte> raw) const override
            {
                ZEUS_EXPECTS(!raw.empty());
                std::string s(reinterpret_cast<const char*>(raw.data()), raw.size());
                auto pos = s.find('\n');

                if (pos == std::string::npos)
                {
                    return std::nullopt;
                }
                return s.substr(0, pos);
            }
    };

    class ZeusLengthPrefixedCodec final : public ZeusPacketCodec
    {
        public:
            /// @pre header_size == 2 || header_size == 4  (uint16 / uint32 length prefix)
            explicit ZeusLengthPrefixedCodec(std::size_t header_size, bool little_endian = true): header_size_{header_size}, little_endian_{little_endian}
            {
                ZEUS_EXPECTS(header_size == 2 || header_size == 4);
            }

            [[nodiscard]]
            std::vector<std::byte> encode(std::string_view payload) const override;

            [[nodiscard]]
            std::optional<std::string> decode(std::span<const std::byte> raw) const override;

        private:
            std::size_t header_size_;
            bool little_endian_;
    };

    class ZeusProtocolService : public zeus::net::ZeusNetworkService
    {
        public:
            using ZeusNetworkService::ZeusNetworkService;

            /// Final Template Method — concrete protocols must NOT override this;
            /// they implement handshake()/authenticate() instead. This keeps the
            /// overall attempt flow (connect -> handshake -> auth -> classify)
            /// identical across all ~50 protocol modules, exactly like the old
            /// hydra_get_next_pair()/hydra_completed_pair() dance, but type-safe
            /// and impossible to get subtly wrong per-module.
            void try_login(zeus::ZeusEngine& engine, std::string_view login, std::string_view password) final
            {
                ZEUS_EXPECTS(!login.empty() || allow_empty_login());
                auto conn = connect_with_policy(engine);

                if (!conn)
                {
                    engine.exit_worker(zeus::ZeusExitCode::no_connect);
                }
                handshake(engine, *conn);
                ZeusAuthResult result = authenticate(engine, *conn, login, password);
                ZEUS_ENSURES(result == ZeusAuthResult::success || result == ZeusAuthResult::failure || result == ZeusAuthResult::retry || result == ZeusAuthResult::protocol_error);

                switch (result)
                {
                    case ZeusAuthResult::success:
                        engine.report_success(std::string{name()}, target_display(engine),std::string{login}, std::string{password});
                        engine.ipc().report_found(login);
                        break;
                    case ZeusAuthResult::failure:
                        break; // just a wrong pair — engine.run() calls report_done()
                    case ZeusAuthResult::retry:
                        engine.exit_worker(zeus::ZeusExitCode::transient_retry);
                        break;
                    case ZeusAuthResult::protocol_error:
                        engine.exit_worker(zeus::ZeusExitCode::protocol_error);
                        break;
                }
            }

        protected:
            /// Optional pre-auth exchange (banner read, STARTTLS, SNI, ...).
            /// Default: no-op — plenty of protocols authenticate immediately.
            virtual void handshake(zeus::ZeusEngine&, ZeusConnection&)
            {

            }

            /// The only method a concrete protocol module MUST implement.
            /// @pre  conn is open
            [[nodiscard]]
            virtual ZeusAuthResult authenticate(zeus::ZeusEngine& engine, ZeusConnection& conn,std::string_view login,std::string_view password) = 0;

            /// A handful of protocols (e.g. VNC) authenticate with password only.
            [[nodiscard]]
            virtual bool allow_empty_login() const noexcept
            {
                return false;
            }

            [[nodiscard]]
            virtual std::string target_display(zeus::ZeusEngine&) const
            {
                return "target";
            }

            [[nodiscard]]
            boost::asio::ip::address resolve_target(zeus::ZeusEngine& engine) const override
            {
                // Default: engine already knows the resolved target address;
                // proxy-aware resolution happens inside Connection::connect_tcp.
                return default_target_address(engine);
            }

        private:
            [[nodiscard]]
            static boost::asio::ip::address default_target_address(zeus::ZeusEngine&);
        };
}













































