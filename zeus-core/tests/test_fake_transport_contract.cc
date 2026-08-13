#include <deque>
#include <gtest/gtest.h>

#include "../lib/zeus_transport.hh"


using namespace zeus::net;

namespace
{
    class FakeTransport final : public ZeusTransport
    {
        public:
            void enqueue_incoming(std::string_view chunk)
            {
                for (char c : chunk)
                {
                    incoming_.push_back(std::byte(c));
                }
            }
            std::expected<std::size_t, ZeusTransportError> write(std::span<const std::byte> data) override
            {
                if (!open_)
                {
                    return std::unexpected(ZeusTransportError::closed);
                }
                written.insert(written.end(), data.begin(), data.end());
                return data.size();
            }
            std::expected<std::size_t, ZeusTransportError> read(std::span<std::byte> buf, std::chrono::milliseconds) override
            {
                if (!open_)
                {
                    return std::unexpected(ZeusTransportError::closed);
                }

                if (incoming_.empty())
                {
                    return std::unexpected(ZeusTransportError::timeout);
                }
                std::size_t n = std::min(buf.size(), incoming_.size());
                std::copy_n(incoming_.begin(), n, buf.begin());
                incoming_.erase(incoming_.begin(), incoming_.begin() + n);
                return n;
            }
            void close() noexcept override
            {
                open_ = false;
            }

            bool is_open() const noexcept override
            {
                return open_;
            }

            std::vector<std::byte> written;
        private:
            std::deque<std::byte> incoming_;
            bool open_ = true;
    };
} // namespace

TEST(FakeTransport, WriteAfterCloseReturnsClosedError)
{
    FakeTransport t;
    t.close();
    std::array<std::byte, 4> data{};
    auto result = t.write(data);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ZeusTransportError::closed);
}

TEST(FakeTransport, ReadReturnsExactlyWhatWasEnqueued)
{
    FakeTransport t;
    t.enqueue_incoming("hi");
    std::array<std::byte, 8> buf{};
    auto n = t.read(buf, std::chrono::milliseconds{0});
    ASSERT_TRUE(n.has_value());
    EXPECT_EQ(*n, 2u);
}





































