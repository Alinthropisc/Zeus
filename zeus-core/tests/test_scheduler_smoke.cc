
#include "zeus.hh"
#include <gtest/gtest.h>

using namespace zeus;

namespace
{
    class AlwaysFailModule final : public Module
    {
        public:
            std::string_view name() const noexcept override
            {
                return "smoke-fake";
            }

            void try_login(Engine&, std::string_view, std::string_view) override
            {
                /* never succeeds */
            }
    };

    static AutoRegister<AlwaysFailModule> reg{"smoke-fake"};
} // namespace

TEST(SchedulerSmoke, RunsToCompletionWithoutHangingOrCrashing)
{
    Options opts;
    opts.server = "127.0.0.1";
    opts.service = "smoke-fake";
    opts.tasks = 2;
    opts.engine.target_port = 1; // guaranteed closed; module ignores connection anyway
    auto targets = TargetExpander::expand(opts);
    auto creds = CredentialSource::brute_force("ab", 1, 1); // just "a", "b"
    Scheduler scheduler(opts, std::move(targets), std::move(creds));
    EXPECT_NO_THROW(scheduler.run());
}