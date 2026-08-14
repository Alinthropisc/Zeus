#pragma once

#include <string>
#include <cstdint>
#include <optional>

namespace zeus::types
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

    struct ZeusConnectOptions {
        ZeusLogLevel log_level{ZeusLogLevel::normal};
        std::chrono::seconds connect_timeout{30};
        std::uint16_t target_port{};
        bool ssl{false};
        std::optional<std::uint16_t> source_port;
        int connect_retries{1};
        bool do_retry{true};
        bool old_ssl{false};
        bool colored_output{true};
        bool quiet{false};
    };

    struct ZeusOptions {
        ZeusAttackMode mode{ZeusAttackMode::password_list};
        bool loop_users{false};
        bool ssl{false};
        bool restore{false};
        ZeusEngine::Options engine{};
        bool show_attempt{false};
        int tasks{16};
        int max_use{16};
        bool try_null_password{false};
        bool try_password_same_as_login{false};
        bool try_password_reverse_login{false};
        bool exit_on_first_found{false};
        bool exit_on_first_found_global{false};
        ZeusOutputFormat outfile_format{ZeusOutputFormat::plain_text};
        std::optional<std::string> distributed; // "X/Y"
        std::optional<std::string> login, login_file;
        std::optional<std::string> password, password_file;
        std::optional<std::filesystem::path> outfile;
        std::optional<std::filesystem::path> targets_file; // -M
        std::optional<std::filesystem::path> colon_file;   // -C
        std::string misc_opts;
        std::string server;
        std::string service;
        bool bruteforce{false}; // -x
        bool skip_redo{false};  // -K
    };

    struct ZeusServiceDescriptor {
        std::string name;
        std::uint16_t default_port{};
        std::uint16_t default_ssl_port{};
    };

    enum class ZeusTargetState {
        active,
        finished,
        error,
        unresolved,
    };

    struct ZeusTarget {
        std::string host;
        std::uint16_t port{};
        std::string resolved_ip;
        ZeusTargetState state{ZeusTargetState::active};
        std::uint64_t login_index{}, pass_index{}, sent{};
        int fail_count{};
        std::vector<ZeusCredential> retry_queue; // было redo_login[]/redo_pass[]
        std::vector<std::string> skip_logins;
    };

    enum class ZeusWorkerState {
        disabled,
        idle,
        active,
    };

    enum class ZeusIsolation {
        thread,
        process,
    };

    struct ZeusNtlmResponse {
        std::vector<std::byte> nt_response;
        std::vector<std::byte> lm_response;
    };
}




































