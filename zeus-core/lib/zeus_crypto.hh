#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "zeus_contract.hh"


namespace zeus::crypto
{
    class ZeusHasher
    {
        public:
            virtual ~ZeusHasher() = default;

            virtual void update(std::span<const std::byte> data) = 0;

            [[nodiscard]]
            virtual std::vector<std::byte> finalize() = 0;

            [[nodiscard]]
            virtual std::size_t digest_size() const noexcept = 0;

            [[nodiscard]]
            virtual std::size_t block_size() const noexcept = 0;

            // HMAC needs a fresh instance of "the same kind of hasher" without
            // knowing the concrete type — classic Prototype-flavoured Strategy.
            [[nodiscard]]
            virtual std::unique_ptr<ZeusHasher> clone_empty() const = 0;
    };


    // MD5 — still in OpenSSL's default provider, wrapped via EVP.
    class ZeusMd5Hasher final : public ZeusHasher
    {
        public:
            ZeusMd5Hasher();
            ~ZeusMd5Hasher() override;
            ZeusMd5Hasher(const ZeusMd5Hasher&) = delete;
            ZeusMd5Hasher& operator=(const ZeusMd5Hasher&) = delete;

            void update(std::span<const std::byte> data) override;

            [[nodiscard]]
            std::vector<std::byte> finalize() override;

            [[nodiscard]]
            std::size_t digest_size() const noexcept override
            {
                return 16;
            }

            [[nodiscard]]
            std::size_t block_size() const noexcept override
            {
                return 64;
            }

            [[nodiscard]]
            std::unique_ptr<ZeusHasher> clone_empty() const override;

        private:
            struct Impl;
            std::unique_ptr<Impl> impl_;
    };

    // MD4 — hand-rolled from RFC 1320. Deliberately NOT via OpenSSL: on stock
    // OpenSSL 3.x, MD4 lives in the "legacy" provider, which most distros don't
    // load by default (confirmed empirically — EVP_EncryptInit_ex on DES/MD4
    // fails with "unsupported" unless you explicitly OSSL_PROVIDER_load("legacy")).
    // NTLM needs MD4 for the NT hash, so we own the implementation instead of
    // depending on a provider that may or may not be present at runtime.
    class ZeusMd4Hasher final : public ZeusHasher
    {
        public:
            ZeusMd4Hasher();

            void update(std::span<const std::byte> data) override;

            [[nodiscard]]
            std::vector<std::byte> finalize() override;

            [[nodiscard]]
            std::size_t digest_size() const noexcept override
            {
                return 16;
            }

            [[nodiscard]]
            std::size_t block_size() const noexcept override
            {
                return 64;
            }

            [[nodiscard]]
            std::unique_ptr<ZeusHasher> clone_empty() const override;

        private:
            void process_block(const std::byte* block) noexcept;

            std::array<std::uint32_t, 4> state_;
            std::vector<std::byte> buffer_;
            std::uint64_t total_len_bits_{0};
    };

    // ---- HMAC, RFC 2104 — composition over ANY ZeusHasher, replaces hmacmd5.c ----
    class ZeusHmac final
    {
        public:
            ZeusHmac(std::unique_ptr<ZeusHasher> hasher, std::span<const std::byte> key);

            void update(std::span<const std::byte> data);

            [[nodiscard]]
            std::vector<std::byte> finalize();

        private:
            std::unique_ptr<ZeusHasher> inner_;
            std::unique_ptr<ZeusHasher> outer_template_;
            std::vector<std::byte> opad_;
    };

    // ---- CRC32 (IEEE 802.3 / zlib polynomial) — replaces crc32.c ----
    // Free function on purpose: it's stateless per call, a class would just be
    // ceremony. Used by the checkpoint/resume integrity check.
    [[nodiscard]] std::uint32_t crc32(std::span<const std::byte> data) noexcept;

    // ---- DES, VNC flavour — replaces d3des.c ----
    // Standard FIPS 46-3 DES engine, verified against the classic all-zero-key
    // vector (8ca64de9c1b123a7) and the "Now is t" textbook vector
    // (3fa40e8a984d4815). The VNC quirk is purely in key preparation: VNC
    // reverses the bit order within each byte of the password before it hits
    // the standard DES key schedule — see reverse_bits_per_byte(). That part
    // is implemented per the documented VNC/d3des behaviour but has NOT been
    // checked yet against a captured real VNC challenge/response — do that
    // before trusting it against a live target.
    class ZeusDesCipher final
    {
    public:
        explicit ZeusDesCipher(std::span<const std::byte, 8> key);

        [[nodiscard]]
        std::array<std::byte, 8> encrypt_block(std::span<const std::byte, 8> plaintext) const noexcept;

    private:
        std::array<std::array<std::byte, 6>, 16> subkeys_{};
    };

    [[nodiscard]]
    std::array<std::byte, 8> vnc_des_key_from_password(std::string_view password) noexcept;
}

























































