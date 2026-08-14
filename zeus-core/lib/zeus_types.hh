#pragma once

#include <string>
#include <cstdint>
#include <optional>

namespace zeus
{
    struct ZeusCredential {
        std::string login;
        std::string password;
    };

    enum class ZeusExitCode : std::uint8_t {
        normal = 0,
        no_connect = 1,
        protocol_error = 2,
        service_down = 3,
        transient_retry = 4,
    };

    enum class ZeusAttackMode : std::uint8_t {
        password_list,
        login_list,
        password_brute,
        password_reverse,
        password_null,
        password_same,
        colon_file,
    };

    enum class ZeusOutputFormat {
        plain_text,
        jsonv1,
        jsonv2,
        xmlv1,
    };

    enum class ZeusKind {
        precondition,
        postcondition,
        invariant,
    };

    enum class ZeusConnectError {
        timeout,
        unreachable,
        proxy_error,
        tls_error,
        io_error,
        need_root,
    };

    enum class ZeusLogLevel {
        quiet,
        normal,
        verbose,
        debug,
    };

    enum class ZeusProxyType {
        none,
        http_connect,
        socks4,
        socks5,
    };

    struct ZeusProxyConfig {
        ZeusProxyType type{ZeusProxyType::none};
        std::string host;
        std::uint16_t port{};
        std::optional<std::string> login;
        std::optional<std::string> password;
    };

    enum class ZeusProxyError {
        negotiation_failed,
        auth_failed,
        io_error,
        unsupported,
    };

    struct ZeusFinding {
        std::uint16_t port{};
        std::string service, host;
        std::optional<std::string> login, password, message;
    };

    enum class ZeusTransportError {
        closed,
        timeout,
        io_error,
    };

    enum class ZeusAuthResult {
        success,        // credentials accepted
        failure,        // credentials rejected (this pair is simply wrong)
        retry,          // transient issue (rate limit, busy) — requeue the pair
        protocol_error, // service spoke something we don't understand — abort target
    };

    enum class ZeusDbDialect {
        postgres,
        mysql,
        mssql,
        oracle,
        redis,
        memcached,
    };
}




































