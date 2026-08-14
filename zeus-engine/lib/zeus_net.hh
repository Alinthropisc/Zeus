#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

#include "../../zeus-core/lib/zeus_contract.hh"
#include "zeus_engine.hh"

namespace zeus::net
{
    class ZeusRetryPolicy
    {
        public:
            virtual ~ZeusRetryPolicy() = default;

            [[nodiscard]]
            virtual std::optional<std::chrono::milliseconds>

            next_delay(int attempt_no) const = 0;
    };

    class ZeusFixedRetryPolicy final : public ZeusRetryPolicy
    {
        public:
            ZeusFixedRetryPolicy(int max_attempts, std::chrono::milliseconds delay): max_attempts_{max_attempts}, delay_{delay}
            {
                ZEUS_EXPECTS(max_attempts >= 0);
            }

            [[nodiscard]]
            std::optional<std::chrono::milliseconds> next_delay(int attempt_no) const override
            {
                ZEUS_EXPECTS(attempt_no >= 1);

                if (attempt_no > max_attempts_)
                {
                    return std::nullopt;
                }
                return delay_;
            }

        private:
            int max_attempts_;
            std::chrono::milliseconds delay_;
    };

    class ZeusExponentialBackoffRetry final : public ZeusRetryPolicy
    {
        public:
            ZeusExponentialBackoffRetry(int max_attempts, std::chrono::milliseconds base,std::chrono::milliseconds cap): max_attempts_{max_attempts}, base_{base}, cap_{cap}
            {
                ZEUS_EXPECTS(max_attempts >= 0);
                ZEUS_EXPECTS(base.count() > 0);
            }

            [[nodiscard]]
            std::optional<std::chrono::milliseconds> next_delay(int attempt_no) const override
            {
                ZEUS_EXPECTS(attempt_no >= 1);

                if (attempt_no > max_attempts_)
                {
                    return std::nullopt;
                }
                auto delay = base_ * (1u << std::min(attempt_no - 1, 16));
                return std::min(delay, cap_);
            }

        private:
            int max_attempts_;
            std::chrono::milliseconds base_, cap_;
    };

    class ZeusRateLimiter final
    {
        public:
            ZeusRateLimiter(double rate_per_sec, std::size_t burst): rate_{rate_per_sec}, capacity_{static_cast<double>(burst)}, tokens_{static_cast<double>(burst)},last_refill_{Clock::now()}
            {
                ZEUS_EXPECTS(rate_per_sec > 0.0);
                ZEUS_EXPECTS(burst >= 1);
            }

            void acquire()
            {
                std::scoped_lock lock{mutex_};
                refill_locked();

                while (tokens_ < 1.0)
                {
                    auto wait = std::chrono::duration<double>((1.0 - tokens_) / rate_);
                    std::this_thread::sleep_for(std::chrono::duration_cast<std::chrono::milliseconds>(wait));
                    refill_locked();
                }
                tokens_ -= 1.0;
                ZEUS_ENSURES(tokens_ >= 0.0);
            }

        private:
            void refill_locked()
            {
                auto now = Clock::now();
                double elapsed = std::chrono::duration<double>(now - last_refill_).count();
                tokens_ = std::min(capacity_, tokens_ + elapsed * rate_);
                last_refill_ = now;
            }
            using Clock = std::chrono::steady_clock;
            double rate_, capacity_, tokens_;
            Clock::time_point last_refill_;
            std::mutex mutex_;
    };

    class ZeusConnectionPool final
    {
    public:
        explicit ZeusConnectionPool(std::size_t max_size) : max_size_{max_size}
        {
            ZEUS_EXPECTS(max_size >= 1);
        }

        /// @post returned pointer is non-null and its socket is either fresh
        ///       from the factory or a previously-returned, still-open one.
        [[nodiscard]]
        std::unique_ptr<ZeusConnection> acquire(zeus::ZeusEngine& engine)
        {
            std::scoped_lock lock{mutex_};

            if (!idle_.empty())
            {
                auto conn = std::move(idle_.front());
                idle_.pop_front();
                return conn;
            }
            return engine.make_connection();
        }

        /// Returns a still-usable connection back to the pool; drops it
        /// otherwise (e.g. after a protocol error that poisoned the stream).
        void release(std::unique_ptr<ZeusConnection> conn, bool reusable)
        {
            ZEUS_EXPECTS(conn != nullptr);
            std::scoped_lock lock{mutex_};

            if (reusable && idle_.size() < max_size_)
            {
                idle_.push_back(std::move(conn));
            }
            // else: unique_ptr destructor closes the socket (RAII)
        }

    private:
        std::size_t max_size_;
        std::deque<std::unique_ptr<Connection>> idle_;
        std::mutex mutex_;
    };

    class ZeusNetworkService : public zeus::ZeusServices
    {
    public:
        explicit ZeusNetworkService(std::unique_ptr<ZeusRetryPolicy> retry,std::shared_ptr<ZeusRateLimiter> limiter = nullptr): retry_{std::move(retry)}, limiter_{std::move(limiter)}
        {
            ZEUS_EXPECTS(retry_ != nullptr);
        }

        ~ZeusNetworkService() override = default;

        /// Template Method: establishes a connection honouring retry policy
        /// and rate limiting, then hands control to the protocol layer via
        /// establish_hook(). Concrete NetworkModule users normally don't call
        /// this directly — ProtocolModule::try_login() does, as the next
        /// layer up in the hierarchy.
        [[nodiscard]]
        std::unique_ptr<ZeusConnection> connect_with_policy(zeus::ZeusEngine& engine)
        {
            ZEUS_EXPECTS(retry_ != nullptr);
            int attempt = 1;

            for (;;)
            {
                if (limiter_)
                {
                    limiter_->acquire();
                }
                auto conn = engine.make_connection();
                auto host = resolve_target(engine);
                auto res = conn->connect_tcp(host, engine.options().target_port,engine.options().connect_timeout);

                if (res)
                {
                    ZEUS_ENSURES(conn != nullptr);
                    return conn;
                }
                auto delay = retry_->next_delay(attempt++);

                if (!delay)
                {
                    return nullptr; // give up, caller must exit_worker(no_connect)
                }
                std::this_thread::sleep_for(*delay);
            }
        }

    protected:
        /// Hook for subclasses to say "where do I connect to" — usually just
        /// the target's resolved IP, but proxy-aware modules can override.
        [[nodiscard]]
        virtual boost::asio::ip::address resolve_target(zeus::ZeusEngine&) const = 0;

    private:
        std::unique_ptr<ZeusRetryPolicy> retry_;
        std::shared_ptr<ZeusRateLimiter> limiter_;
    };
}













































