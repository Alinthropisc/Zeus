#include <iostream>
#include <csignal>

#include <boost/program_options.hpp>

#include "zeus.hh"
#include "zeus_types.hh"


namespace zeus
{
    namespace po = boost::program_options;

    inline constexpr std::string_view kProgram = "zeus";
    inline constexpr std::string_view kVersion = "v1.0";

    ZeusOptions ZeusOptionsParser::parse(int argc, char **argv)
    {
        ZeusOptions opts;
        po::options_description desc("Zeus Options");
        desc.add_options()
                ("login,l", po::value<std::string>(), "single login")
                ("login-file,L", po::value<std::string>(), "login list file")
                ("password,p", po::value<std::string>(), "single password")
                ("password-file,P", po::value<std::string>(), "password list file")
                ("colon-file,C", po::value<std::string>(), "login:pass colon file")
                ("targets-file,M", po::value<std::string>(), "targets list file")
                ("tasks,t", po::value<int>()->default_value(16), "parallel tasks per target")
                ("ssl,S", po::bool_switch(), "force SSL connect")
                ("restore,R", po::bool_switch(), "resume previous session")
                ("verbose,v", po::bool_switch(), "verbose mode")
                ("debug,d", po::bool_switch(), "debug mode")
                ("quiet,q", po::bool_switch(), "quiet mode")
                ("service", po::value<std::string>(), "service://server[:port][/opts]");
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc).run(), vm);
        po::notify(vm);

        if (vm.count("login-file"))
        {
            opts.login_file = vm["login-file"].as<std::string>();
        }

        if (vm.count("password-file"))
        {
            opts.password_file = vm["password-file"].as<std::string>();
        }

        if (vm.count("tasks"))
        {
            opts.tasks = vm["tasks"].as<int>();
        }
        opts.ssl = vm["ssl"].as<bool>();
        opts.restore = vm["restore"].as<bool>();
        opts.engine.log_level = vm["debug"].as<bool>() ? zeus::ZeusLogLevel::debug : vm["verbose"].as<bool>() ? zeus::ZeusLogLevel::verbose : zeus::ZeusLogLevel::normal;
        opts.engine.quiet = vm["quiet"].as<bool>();
        // ... остальное аналогично ...
        return opts;
    }

    ZeusServiceCatalog::ZeusServiceCatalog() = default;

    ZeusServiceCatalog& ZeusServiceCatalog::instance()
    {
        static ZeusServiceCatalog cat;
        return cat;
    }

    std::optional<ZeusServiceDescriptor> ZeusServiceCatalog::find(std::string_view name) const
    {
        auto module = ZeusServicesRegistry::instance().create(name);
        if (!module)
        {
            return std::nullopt;
        }
        return module->descriptor();
    }

    std::vector<std::string> ZeusServiceCatalog::all_names() const
    {
        return ZeusServicesRegistry::instance().available();
    }

// --------------------------------------------------------------- Scheduler --
    ZeusScheduler::ZeusScheduler(ZeusOptions opts, std::vector<ZeusTarget> targets, ZeusCredentialSource creds) : opts_{std::move(opts)}, targets_{std::move(targets)}, creds_{std::move(creds)}
    {

    }

    void ZeusScheduler::run()
    {
        // Command pattern: у каждой цели создаём Worker'ов по opts_.tasks,
        // каждый Worker в своём jthread крутит Engine::run(module) поверх
        // общего CredentialSource (thread-safe очередь пар).
        for (auto& target : targets_)
        {
            for (int i = 0; i < opts_.tasks; ++i)
            {
                auto module = ZeusServicesRegistry::instance().create(opts_.service);

                if (!module)
                {
                    throw std::runtime_error("unknown service: " + opts_.service);
                }
                auto worker = std::make_unique<ZeusWorker>(target, std::move(module), ZeusWorker::ZeusIsolation::thread);
                worker->start(creds_, opts_.engine);
                workers_.push_back(std::move(worker));
            }
        }
        // ждём завершения всех воркеров (jthread джойнится в деструкторе)
        workers_.clear();
    }

// -------------------------------------------------------------- Application --
    int ZeusApplication::run(int argc, char** argv)
    {
        auto opts = ZeusOptionsParser::parse(argc, argv);

        if (opts.restore)
        {
            auto session = ZeusRestoreSession::load("./zeus.restore");

            if (!session)
            {
                std::cerr << "[ ETA ]: ERROR no restore file\n";
                return -1;
            }
            opts = session->options;
        }
        auto targets = ZeusTargetExpander::expand(opts);
        auto creds = opts.colon_file ? ZeusCredentialSource::from_colon_file(*opts.colon_file) : ZeusCredentialSource::from_files(opts.login_file, opts.password_file);
        ZeusScheduler scheduler(opts, std::move(targets), std::move(creds));
        ZeusSignalGuard guard(scheduler); // ставит SIGINT/SIGTERM -> корректная запись restore + выход
        scheduler.run();
        std::cout << std::format("[ ETA ]: Found {} valid pairs, {} attempts sent.\n",scheduler.stats().found(), scheduler.stats().sent());
        return 0;
    }

} // namespace zeus




int main(int argc, char** argv)
{
    return zeus::ZeusApplication{}.run(argc, argv);
}




















































































