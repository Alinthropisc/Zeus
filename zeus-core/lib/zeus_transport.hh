#pragma once

#include <cstddef>
#include <expected>
#include <span>

#include "zeus_types.hh"

namespace zeus::net
{

//    enum class ZeusTransportError {
//        closed,
//        timeout,
//        io_error,
//    };

    class ZeusTransport
    {
        public:
            virtual ~ZeusTransport() = default;

            [[nodiscard]]
            virtual std::expected<std::size_t, ZeusTransportError>

            write(std::span<const std::byte> data) = 0;

            [[nodiscard]]
            virtual std::expected<std::size_t, ZeusTransportError>

            read(std::span<std::byte> buffer, std::chrono::milliseconds timeout) = 0;
            virtual void close() noexcept = 0;

            [[nodiscard]]
            virtual bool is_open() const noexcept = 0;
    };

}








































