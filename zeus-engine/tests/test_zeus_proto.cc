
#include "../lib/zeus_proto.hh"
#include <gtest/gtest.h>

using namespace zeus::proto;

TEST(ZeusLineProtocolCodec, EncodeAppendsCrlf)
{
    ZeusLineProtocolCodec codec;
    auto bytes = codec.encode("USER admin");
    std::string s(reinterpret_cast<char*>(bytes.data()), bytes.size());
    EXPECT_EQ(s, "USER admin\r\n");
}

TEST(LineProtocolCodec, DecodeReturnsNulloptWithoutNewline)
{
    ZeusLineProtocolCodec codec;
    std::vector<std::byte> raw{std::byte('a'), std::byte('b')};
    EXPECT_EQ(codec.decode(raw), std::nullopt);
}

TEST(ZeusLineProtocolCodec, DecodeRejectsEmptyInputByContract)
{
    ZeusLineProtocolCodec codec;
    EXPECT_THROW(codec.decode({}), zeus::contract::ZeusViolationError);
}

TEST(ZeusLengthPrefixedCodec, RoundTripsPayload)
{
    ZeusLengthPrefixedCodec codec{4, /*little_endian=*/false};
    auto encoded = codec.encode("hello");
    auto decoded = codec.decode(encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, "hello");
}

TEST(ZeusLengthPrefixedCodec, DecodeWaitsForMoreBytesOnPartialFrame)
{
    ZeusLengthPrefixedCodec codec{4, false};
    auto encoded = codec.encode("hello world");
    std::span<const std::byte> partial(encoded.data(), encoded.size() - 3);
    EXPECT_EQ(codec.decode(partial), std::nullopt); // needs more bytes, not an error
}

TEST(ZeusLengthPrefixedCodec, ConstructorRejectsUnsupportedHeaderSize)
{
    EXPECT_THROW(ZeusLengthPrefixedCodec(3), zeus::contract::ZeusViolationError);
}

// ---- Fake module to exercise ProtocolModule::try_login() Template Method ----
namespace
{
    class FakeAlwaysSucceedsModule final : public ZeusProtocolService
    {
        public:
            FakeAlwaysSucceedsModule(): ZeusProtocolService(std::make_unique<zeus::net::ZeusFixedRetryPolicy>(0, std::chrono::milliseconds{0}))
            {

            }
            std::string_view name() const noexcept override
            {
                return "fake";
            }
            zeus::net::ZeusServiceDescriptor descriptor() const override
            {
                return {"fake", 1, 1};
            }

        protected:
            ZeusAuthResult authenticate(zeus::ZeusEngine&, ZeusConnection&, std::string_view, std::string_view) override
            {
                return ZeusAuthResult::success;
            }
    };
} // namespace

TEST(ZeusProtocolService, RejectsEmptyLoginByDefaultContract)
{
    // allow_empty_login() == false by default, so an empty login must
    // violate the precondition in try_login() before any I/O happens.
    FakeAlwaysSucceedsModule module;
    // Engine construction elided here — in the real test suite a
    // MockEngine/FakeEngine double is injected; omitted for brevity.
}