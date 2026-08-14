#pragma once

#include <format>
#include <source_location>
#include <stdexcept>
#include <string>

#include "zeus_types.hh"

namespace zeus::contract
{
//    enum class ZeusKind {
//        precondition,
//        postcondition,
//        invariant,
//    };

    class ZeusViolationError final : public std::logic_error
    {
        public:
            ZeusViolationError(zeus::ZeusKind kind, const char* expr, std::source_location loc): std::logic_error(std::format("[{}] contract violated: `{}` at {}:{} in {}()",kind_name(kind), expr, loc.file_name(),loc.line(), loc.function_name())),kind_{kind}
            {

            }

            [[nodiscard]]
            zeus::ZeusKind kind() const noexcept
            {
                return kind_;
            }

        private:
            static constexpr const char* kind_name(ZeusKind k) noexcept
            {
                switch (k)
                {
                    case ZeusKind::precondition:
                        return "PRECONDITION";
                        break;
                    case ZeusKind::postcondition:
                        return "POSTCONDITION";
                        break;
                    case ZeusKind::invariant:
                        return "INVARIANT";
                        break;
                }
                return "UNKNOWN";
            }
            ZeusKind kind_;
    };

    [[noreturn]]
    inline void fail(zeus::ZeusKind kind, const char* expr,std::source_location loc = std::source_location::current())
    {
        throw ZeusViolationError(kind, expr, loc);
    }

    template <typename Self, typename Predicate> class ZeusInvariantGuard final
    {
        public:
            ZeusInvariantGuard(const Self&, Predicate pred, std::source_location loc = std::source_location::current()): pred_{std::move(pred)}, loc_{loc}
            {
                if (!pred_())
                {
                    fail(ZeusKind::invariant, "on entry", loc_);
                }
            }
            ~ZeusInvariantGuard() noexcept(false) {
                if (!pred_())
                {
                    fail(ZeusKind::invariant, "on exit", loc_);
                }
            }
            ZeusInvariantGuard(const ZeusInvariantGuard&) = delete;

        private:
            Predicate pred_;
            std::source_location loc_;
    };

}


#ifdef ZEUS_DISABLE_CONTRACTS
#define ZEUS_EXPECTS(cond) ((void)0)
#define ZEUS_ENSURES(cond) ((void)0)
#define ZEUS_INVARIANT(cond) ((void)0)
#else
#define ZEUS_EXPECTS(cond) ((cond) ? (void)0 : ::zeus::contract::fail(::zeus::ZeusKind::precondition, #cond))
#define ZEUS_ENSURES(cond) ((cond) ? (void)0 : ::zeus::contract::fail(::zeus::ZeusKind::postcondition, #cond))
#define ZEUS_INVARIANT(cond) ((cond) ? (void)0 : ::zeus::contract::fail(::zeus::ZeusKind::invariant, #cond))
#endif




























































