#pragma once

#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>


namespace zeus
{
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

    enum class OutputFormat {
        plain_text,
        jsonv1,
        jsonv2,
        xmlv1,
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
        OutputFormat outfile_format{OutputFormat::plain_text};
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

    class ZeusEngine;

    class ZeusEngineExit final
    {
        public:
            explicit ZeusEngineExit(ZeusExitCode code) noexcept : code_(code)
            {

            }

            [[nodiscard]]
            ZeusExitCode code() const noexcept
            {
                return code_;
            }

        private:
            ZeusExitCode code_;
    };

    struct ZeusServiceDescriptor {
        std::string name;
        std::uint16_t default_port{};
        std::uint16_t default_ssl_port{};
    };

    class ZeusServices
    {
        public:
            virtual ~ZeusServices() = default;

            [[nodiscard]]
            virtual std::string_view name() const noexcept = 0;

            [[nodiscard]]
            virtual ZeusServiceDescriptor descriptor() const = 0;

            virtual void init(ZeusEngine&)
            {

            }

            virtual void try_login(ZeusEngine&, std::string_view login, std::string_view password) = 0;

            virtual void usage(std::ostream& os) const
            {
                os << "This module has no extra options.\n";
            }
    };



    class ZeusServicesRegistry
    {
        public:
            using ZeusFactory = std::function<std::unique_ptr<ZeusServices>()>;

            static ZeusServicesRegistry &instance()
            {
                static ZeusServicesRegistry registry;
                return registry;
            }

            void register_service(std::string name, ZeusFactory factory)
            {
                factories_.emplace(std::move(name), std::move(factory));
            }

            [[nodiscard]]
            std::unique_ptr<ZeusServices> create(std::string_view name) const
            {
                auto it = factories_.find(std::string(name));
                return it != factories_.end() ? it->second() : nullptr;
            }

            [[nodiscard]]
            auto available() const
            {
                std::vector<std::string> names;
                names.reserve(factories_.size());

                for (auto &[k, _] : factories_)
                {
                    names.push_back(k);
                }
                return names;
            }

        private:
            ZeusServicesRegistry() = default;
            std::unordered_map<std::string, ZeusFactory> factories_;
    };


    class ZeusOptionsParser final
    {
        public:
            [[nodiscard]]
            static ZeusOptions parse(int argc, char** argv);
    };

    class ZeusServiceCatalog final
    {
        public:
            static ZeusServiceCatalog& instance();
            [[nodiscard]]
            std::optional<ZeusServiceDescriptor> find(std::string_view name) const;

            [[nodiscard]]
            std::vector<std::string> all_names() const;

            void print_supported(std::ostream&) const;
        private:
            ZeusServiceCatalog();
    };

    enum class ZeusTargetState {
        active,
        finished,
        error,
        unresolved,
    };

/// Заменяет hydra_target.
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

/// Строит список целей из "server", CIDR (192.168.0.0/24), файла -M, [ipv6].
/// Заменяет ручной CIDR-цикл и парсинг -M в main().
    class ZeusTargetExpander final
    {
        public:
            [[nodiscard]]
            static std::vector<ZeusTarget> expand(const ZeusOptions& opts);
    };

// ------------------------------------------------------------- Credential --
/// Заменяет fill_mem()/countlines(): ленивое, не съедающее память чтение
/// словарей логинов/паролей (mmap + view, а не malloc всего файла разом).
    class ZeusCredentialSource final
    {
        public:
            static ZeusCredentialSource from_files(std::optional<std::filesystem::path> logins,std::optional<std::filesystem::path> passwords);
            static ZeusCredentialSource from_colon_file(const std::filesystem::path& path);
            static ZeusCredentialSource brute_force(std::string_view charset, std::size_t min_len, std::size_t max_len);

            [[nodiscard]]
            std::generator<std::string> logins() const;

            [[nodiscard]]
            std::generator<std::string> passwords() const;

            [[nodiscard]]
            std::uint64_t login_count() const noexcept
            {
                return login_count_;
            }

            [[nodiscard]]
            std::uint64_t pass_count()  const noexcept
            {
                return pass_count_;
            }

        private:
            std::uint64_t login_count_{}, pass_count_{};
            // детали хранения: mmap-диапазоны или std::generator для брутфорса
    };

// --------------------------------------------------------------- Worker/Scheduler --
    enum class ZeusWorkerState {
        disabled,
        idle,
        active,
    };

/// Заменяет hydra_head + fork()/socketpair(). Один Worker = одна "голова"
/// перебора для одной цели. По умолчанию — std::jthread (быстрее, легче),
/// опционально — изолированный процесс (для хрупких библиотек типа libssh).
    class ZeusWorker final
    {
    public:
        enum class ZeusIsolation {
            thread,
            process,
        };

        ZeusWorker(ZeusTarget& target, std::unique_ptr<Module> module, ZeusIsolation isolation);
        ~ZeusWorker();

        void start(ZeusCredentialSource& creds, ZeusEngine::Options opts);
        void request_stop();

        [[nodiscard]]
        ZeusWorkerState state() const noexcept
        {
            return state_;
        }

        [[nodiscard]]
        std::optional<ZeusCredential> last_pair() const
        {
            return last_pair_;
        }

    private:
        ZeusTarget* target_;
        std::unique_ptr<Module> module_;
        ZeusIsolation isolation_;
        std::atomic<ZeusWorkerState> state_{ZeusWorkerState::idle};
        std::optional<ZeusCredential> last_pair_;
        std::jthread thread_;      // isolation == thread
        pid_t pid_{-1};            // isolation == process
        int ipc_fd_{-1};
    };

/// Заменяет весь пул hydra_heads[] + ручное round-robin распределение
/// в главном цикле main(). Command pattern: каждый Worker выполняет
/// "попробовать следующую пару" как самостоятельную единицу работы.
    class ZeusScheduler final
    {
        public:
            ZeusScheduler(ZeusOptions opts, std::vector<ZeusTarget> targets, ZeusCredentialSource creds);
            void run();                 // блокирующий главный цикл (было: while(1) в main())

            [[nodiscard]]
            ZeusStatsBoard& stats() noexcept
            {
                return stats_;
            }

        private:
            ZeusOptions opts_;
            std::vector<ZeusTarget> targets_;
            ZeusCredentialSource creds_;
            std::vector<std::unique_ptr<ZeusWorker>> workers_;
            ZeusStatsBoard stats_;
            ZeusRestoreSession restore_;
    };

// ----------------------------------------------------------------- StatsBoard --
/// Заменяет hydra_brain. Observer: воркеры дергают методы, UI/лог подписан.
    class ZeusStatsBoard final
    {
        public:
            void on_attempt() noexcept
            {
                ++sent_;
            }

            void on_found() noexcept
            {
                ++found_;
            }

            void on_target_finished() noexcept
            {
                ++finished_targets_;
            }

            [[nodiscard]]
            std::uint64_t sent() const noexcept
            {
                return sent_;
            }

            [[nodiscard]]
            std::uint64_t found() const noexcept
            {
                return found_;
            }

        private:
            std::atomic<std::uint64_t> sent_{}, found_{}, finished_targets_{};
    };

// -------------------------------------------------------------- RestoreSession --
/// Заменяет hydra_restore_write/read (был ручной fwrite/fread структур —
/// хрупко к ABI). Memento + бинарная сериализация с версионированием
/// (Boost.Serialization или самодельный формат с magic+version+CRC32).
    class ZeusRestoreSession final
    {
        public:
            static constexpr std::string_view kMagic = "ZEUS-RESTORE";
            static constexpr std::uint32_t kFormatVersion = 1;

            void save(const std::filesystem::path& file, const ZeusOptions&,const std::vector<ZeusTarget>&, const ZeusStatsBoard&) const;

            [[nodiscard]]
            static std::optional<ZeusRestoreSession> load(const std::filesystem::path& file);

            ZeusOptions options;
            std::vector<ZeusTarget> targets;
    };

    class ZeusSignalGuard final
    {
        public:
            explicit ZeusSignalGuard(ZeusScheduler& scheduler);
            ZeusSignalGuard(const ZeusSignalGuard&) = delete;
            ~ZeusSignalGuard();

        private:
            ZeusScheduler& scheduler_;
    };

    class ZeusApplication final
    {
        public:
            int run(int argc, char** argv);
        private:
            void print_help(bool extended) const;   // было help(int32_t ext)
            void print_module_usage(const Options&) const; // было module_usage()
    };
}


// Auto Registry Services in static link init
// example: static zeus::ZeusAutoRegister<PostgreSQLService> reg_postgresql{"postgresql"};
template<typename ZeusServicesT> struct ZeusAutoRegister {
    explicit ZeusAutoRegister(std::string name) {
        zeus::ZeusServicesRegistry::instance().register_service(std::move(name), [] {
            return std::make_unique<ZeusServicesT>();
        });
    }
};











































