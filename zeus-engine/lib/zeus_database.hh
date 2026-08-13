#pragma once

#include <string>

#include "../../zeus-core/lib/zeus_contract.hh"
#include "zeus_proto.hh"
#include "zeus_sasl.hh"   // zeus::crypto::SaslExchange / SaslExchangeFactory

namespace zeus::database
{
    enum class ZeusDbDialect {
        postgres,
        mysql,
        mssql,
        oracle,
        redis,
        memcached,
    };

    class ZeusDatabaseService : public zeus::proto::ZeusProtocolService
    {
        public:
            ZeusDatabaseService(std::unique_ptr<zeus::net::ZeusRetryPolicy> retry, ZeusDbDialect dialect): ZeusProtocolService(std::move(retry)), dialect_{dialect}
            {

            }

            [[nodiscard]]
            ZeusDbDialect dialect() const noexcept
            {
                return dialect_;
            }

        protected:
            /// Concrete DB module builds its own startup/handshake packet
            /// (protocol version, database name, requested auth methods).
            /// @post returned buffer is non-empty
            [[nodiscard]]
            virtual std::vector<std::byte> build_startup_packet(std::string_view user, std::string_view database) const = 0;

            /// Concrete DB module decides which SASL mechanism the server asked
            /// for (inspecting the startup response) — Factory Method.
            [[nodiscard]]
            virtual std::unique_ptr<zeus::crypto::SaslExchange> select_mechanism(std::string_view server_hello, std::string_view user,std::string_view password) const = 0;

            /// Drives a generic challenge-response loop:
            ///   client_first -> server_first -> client_final -> server_final
            /// Shared by every SASL-based DB (Postgres SCRAM-SHA-256, MySQL
            /// caching_sha2_password, ...) instead of four separate hand-rolled
            /// state machines like in the original sasl.c/ntlm.c.
            [[nodiscard]]
            zeus::proto::ZeusAuthResult perform_sasl_exchange(zeus::proto::ZeusPacketCodec& codec, ZeusConnection& conn,zeus::crypto::SaslExchange& exchange)
            {
                ZEUS_EXPECTS(&exchange != nullptr);
                auto first = exchange.client_first_message();
                auto raw = codec.encode(first);

                if (!conn.send(raw))
                {
                    return zeus::proto::ZeusAuthResult::protocol_error;
                }
                std::array<std::byte, 4096> buf{};
                auto n = conn.receive(buf, std::chrono::milliseconds{3000});

                if (!n)
                {
                    return zeus::proto::ZeusAuthResult::retry; // timeout: server busy, requeue
                }
                auto server_first = codec.decode(std::span(buf).first(*n));

                if (!server_first)
                {
                    return zeus::proto::ZeusAuthResult::protocol_error;
                }
                auto final_msg = exchange.client_final_message(*server_first);
                raw = codec.encode(final_msg);

                if (!conn.send(raw))
                {
                    return zeus::proto::ZeusAuthResult::protocol_error;
                }
                n = conn.receive(buf, std::chrono::milliseconds{3000});

                if (!n)
                {
                    return zeus::proto::ZeusAuthResult::retry;
                }
                auto server_final = codec.decode(std::span(buf).first(*n));

                if (!server_final)
                {
                    return zeus::proto::ZeusAuthResult::protocol_error;
                }
                bool ok = exchange.verify_server_signature(*server_final);
                ZEUS_ENSURES(true); // exchange object fully consumed either way
                return ok ? zeus::proto::ZeusAuthResult::success : zeus::proto::ZeusAuthResult::failure;
            }

        private:
            ZeusDbDialect dialect_;
    };
}















































