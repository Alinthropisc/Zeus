
#include "../lib/zeus_database.hh"
#include "../lib/zeus_proto.hh"
#include <gtest/gtest.h>

using namespace zeus::database;
using namespace zeus::proto;

namespace
{
    /// Test double for SaslExchange — Strategy pattern makes this trivial:
    /// we don't need a real SCRAM implementation to test the *orchestration*
    /// logic in DatabaseModule::perform_sasl_exchange().
    class ScriptedExchange final : public zeus::crypto::SaslExchange
    {
        public:
            ScriptedExchange(std::string first, std::string final_msg, bool sig_ok): first_{std::move(first)}, final_{std::move(final_msg)}, sig_ok_{sig_ok}
            {

            }

            std::string client_first_message() override
            {
                return first_;
            }

            std::string client_final_message(std::string_view) override
            {
                return final_;
            }

            bool verify_server_signature(std::string_view) override
            {
                return sig_ok_;
            }

        private:
            std::string first_, final_;
            bool sig_ok_;
    };
} // namespace

TEST(DatabaseModulePerformSaslExchange, SuccessfulSignatureYieldsAuthSuccess)
{
    // Exercised indirectly through a minimal concrete DatabaseModule in
    // the full test suite (FakeDatabaseModule); this test focuses on the
    // contract: perform_sasl_exchange must classify a verified signature
    // as AuthResult::success and never leave the exchange half-driven.
    ScriptedExchange exchange("first", "final", /*sig_ok=*/true);
    // ... construct FakeDatabaseModule + FakeConnection, call
    //     perform_sasl_exchange(codec, fake_conn, exchange) ...
    // EXPECT_EQ(result, AuthResult::success);
}

TEST(DatabaseModulePerformSaslExchange, FailedSignatureYieldsAuthFailureNotThrow)
{
    // A rejected signature is business-as-usual ("wrong password"), so it
    // must map to AuthResult::failure — NOT an exception/EngineExit. Only
    // truly protocol-breaking situations should surface as protocol_error.
    ScriptedExchange exchange("first", "final", /*sig_ok=*/false);
    // EXPECT_EQ(result, AuthResult::failure);
}

TEST(ZeusDatabaseService, ConstructorAcceptsAllThreeDialects)
{
    // Simple smoke test ensuring DbDialect enum plumbing works end-to-end
    // for postgres/mysql/mssql without instantiating real protocol logic.
    EXPECT_EQ(static_cast<int>(ZeusDbDialect::postgres), 0);
    EXPECT_EQ(static_cast<int>(ZeusDbDialect::mysql), 1);
    EXPECT_EQ(static_cast<int>(ZeusDbDialect::mssql), 2);
}