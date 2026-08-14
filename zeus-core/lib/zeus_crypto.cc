#include <cstring>
#include <openssl/evp.h>

#include "zeus_crypto.hh"

namespace zeus::crypto
{
    struct ZeusMd5Hasher::Impl {
        EVP_MD_CTX* ctx{nullptr};
    };

    ZeusMd5Hasher::ZeusMd5Hasher() : impl_{std::make_unique<Impl>()}
    {
        impl_->ctx = EVP_MD_CTX_new();
        ZEUS_EXPECTS(impl_->ctx != nullptr);
        EVP_DigestInit_ex(impl_->ctx, EVP_md5(), nullptr);
    }

    ZeusMd5Hasher::~ZeusMd5Hasher()
    {
        if (impl_ && impl_->ctx)
        {
            EVP_MD_CTX_free(impl_->ctx);
        }
    }

    void ZeusMd5Hasher::update(std::span<const std::byte> data)
    {
        EVP_DigestUpdate(impl_->ctx, data.data(), data.size());
    }

    std::vector<std::byte> ZeusMd5Hasher::finalize()
    {
        std::vector<std::byte> out(EVP_MAX_MD_SIZE);
        unsigned int len = 0;
        EVP_DigestFinal_ex(impl_->ctx, reinterpret_cast<unsigned char*>(out.data()), &len);
        out.resize(len);
        ZEUS_ENSURES(out.size() == digest_size());
        return out;
    }

    std::unique_ptr<ZeusHasher> ZeusMd5Hasher::clone_empty() const
    {
        return std::make_unique<ZeusMd5Hasher>();
    }

    namespace
    {
        constexpr std::uint32_t rotl32(std::uint32_t x, int n) noexcept
        {
            return (x << n) | (x >> (32 - n));
        }

        constexpr std::uint32_t md4_f(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
        {
            return (x & y) | (~x & z);
        }

        constexpr std::uint32_t md4_g(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
        {
            return (x & y) | (x & z) | (y & z);
        }

        constexpr std::uint32_t md4_h(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
        {
            return x ^ y ^ z;
        }
    }

    ZeusMd4Hasher::ZeusMd4Hasher(): state_{0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u}
    {

    }

    void ZeusMd4Hasher::update(std::span<const std::byte> data)
    {
        buffer_.insert(buffer_.end(), data.begin(), data.end());
        total_len_bits_ += static_cast<std::uint64_t>(data.size()) * 8;

        while (buffer_.size() >= 64)
        {
            process_block(buffer_.data());
            buffer_.erase(buffer_.begin(), buffer_.begin() + 64);
        }
    }

    void ZeusMd4Hasher::process_block(const std::byte* block) noexcept
    {
        std::uint32_t x[16];

        for (int i = 0; i < 16; ++i)
        {
            x[i] = static_cast<std::uint32_t>(block[i * 4]) | (static_cast<std::uint32_t>(block[i * 4 + 1]) << 8) | (static_cast<std::uint32_t>(block[i * 4 + 2]) << 16) | (static_cast<std::uint32_t>(block[i * 4 + 3]) << 24);
        }
        std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];

        for (int i = 0; i < 16; i += 4)
        {
            a = rotl32(a + md4_f(b, c, d) + x[i + 0], 3);
            d = rotl32(d + md4_f(a, b, c) + x[i + 1], 7);
            c = rotl32(c + md4_f(d, a, b) + x[i + 2], 11);
            b = rotl32(b + md4_f(c, d, a) + x[i + 3], 19);
        }
        constexpr std::uint32_t k2 = 0x5A827999u;

        for (int i = 0; i < 4; ++i)
        {
            a = rotl32(a + md4_g(b, c, d) + x[i + 0]  + k2, 3);
            d = rotl32(d + md4_g(a, b, c) + x[i + 4]  + k2, 5);
            c = rotl32(c + md4_g(d, a, b) + x[i + 8]  + k2, 9);
            b = rotl32(b + md4_g(c, d, a) + x[i + 12] + k2, 13);
        }
        constexpr std::uint32_t k3 = 0x6ED9EBA1u;
        constexpr int order[4] = {0, 2, 1, 3};

        for (int idx = 0; idx < 4; ++idx)
        {
            const int i = order[idx];
            a = rotl32(a + md4_h(b, c, d) + x[i + 0]  + k3, 3);
            d = rotl32(d + md4_h(a, b, c) + x[i + 8]  + k3, 9);
            c = rotl32(c + md4_h(d, a, b) + x[i + 4]  + k3, 11);
            b = rotl32(b + md4_h(c, d, a) + x[i + 12] + k3, 15);
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    }

    std::vector<std::byte> ZeusMd4Hasher::finalize()
    {
        const std::uint64_t bit_len = total_len_bits_;
        std::vector<std::byte> pad;
        pad.push_back(std::byte{0x80});
        const std::size_t cur = buffer_.size() + 1;
        const std::size_t need = (cur % 64 <= 56) ? (56 - cur % 64) : (120 - cur % 64);
        pad.insert(pad.end(), need, std::byte{0});

        for (int i = 0; i < 8; ++i)
        {
            pad.push_back(static_cast<std::byte>((bit_len >> (8 * i)) & 0xFF));
        }
        update(pad);
        ZEUS_ENSURES(buffer_.empty());
        std::vector<std::byte> out(16);

        auto put = [&out](int off, std::uint32_t v)
        {
            out[off + 0] = static_cast<std::byte>(v & 0xFF);
            out[off + 1] = static_cast<std::byte>((v >> 8) & 0xFF);
            out[off + 2] = static_cast<std::byte>((v >> 16) & 0xFF);
            out[off + 3] = static_cast<std::byte>((v >> 24) & 0xFF);
        };
        put(0, state_[0]); put(4, state_[1]); put(8, state_[2]); put(12, state_[3]);
        return out;
    }

    std::unique_ptr<ZeusHasher> ZeusMd4Hasher::clone_empty() const
    {
        return std::make_unique<ZeusMd4Hasher>();
    }

    // ============================== HMAC (RFC 2104) ==============================
    ZeusHmac::ZeusHmac(std::unique_ptr<ZeusHasher> hasher, std::span<const std::byte> key)
    {
        ZEUS_EXPECTS(hasher != nullptr);
        const std::size_t bs = hasher->block_size();
        std::vector<std::byte> k(key.begin(), key.end());

        if (k.size() > bs)
        {
            auto tmp = hasher->clone_empty();
            tmp->update(k);
            k = tmp->finalize();
        }
        k.resize(bs, std::byte{0});
        std::vector<std::byte> ipad(bs), opad(bs);

        for (std::size_t i = 0; i < bs; ++i)
        {
            ipad[i] = k[i] ^ std::byte{0x36};
            opad[i] = k[i] ^ std::byte{0x5c};
        }
        inner_ = hasher->clone_empty();
        inner_->update(ipad);
        outer_template_ = std::move(hasher);
        opad_ = std::move(opad);
    }

    void ZeusHmac::update(std::span<const std::byte> data)
    {
        inner_->update(data);
    }

    std::vector<std::byte> ZeusHmac::finalize()
    {
        auto inner_digest = inner_->finalize();
        auto outer = outer_template_->clone_empty();
        outer->update(opad_);
        outer->update(inner_digest);
        return outer->finalize();
    }

    std::uint32_t crc32(std::span<const std::byte> data) noexcept
    {
        static constexpr auto table = []
        {
            std::array<std::uint32_t, 256> t{};

            for (std::uint32_t i = 0; i < 256; ++i)
            {
                std::uint32_t c = i;

                for (int k = 0; k < 8; ++k)
                {
                    c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
                }
                t[i] = c;
            }
            return t;
        }();
        std::uint32_t crc = 0xFFFFFFFFu;

        for (auto b : data)
        {
            crc = table[(crc ^ static_cast<unsigned char>(b)) & 0xFF] ^ (crc >> 8);
        }
        return crc ^ 0xFFFFFFFFu;
    }

    namespace
    {
        constexpr int kIp[64] = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
                                 62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
                                 57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
                                 61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
        constexpr int kFp[64] = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
                                 38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
                                 36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
                                 34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
        constexpr int kE[48] = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
                                12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,
                                24,25,26,27,28,29,28,29,30,31,32,1};
        constexpr int kP[32] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
                                2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
        constexpr int kPc1[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,
                                  10,2,59,51,43,35,27,19,11,3,60,52,44,36,
                                  63,55,47,39,31,23,15,7,62,54,46,38,30,22,
                                  14,6,61,53,45,37,29,21,13,5,28,20,12,4};
        constexpr int kPc2[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,
                                  16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,
                                  44,49,39,56,34,53,46,42,50,36,29,32};
        constexpr int kShifts[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
        constexpr int kSbox[8][4][16] = {
                {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
                {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
                {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
                {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
                {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
                {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
                {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
                {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}},
        };
        using BitArr64 = std::array<int, 64>;
        using BitArr56 = std::array<int, 56>;
        using BitArr48 = std::array<int, 48>;
        using BitArr32 = std::array<int, 32>;

        BitArr64 bytes_to_bits(std::span<const std::byte, 8> b) noexcept
        {
            BitArr64 bits{};

            for (int i = 0; i < 8; ++i)
            {
                auto byte = static_cast<unsigned char>(b[i]);
                for (int j = 0; j < 8; ++j) { bits[i * 8 + j] = (byte >> (7 - j)) & 1; }
            }
            return bits;
        }

        std::array<std::byte, 8> bits_to_bytes(const BitArr64& bits) noexcept
        {
            std::array<std::byte, 8> out{};

            for (int i = 0; i < 8; ++i)
            {
                unsigned char v = 0;
                for (int j = 0; j < 8; ++j) { v = static_cast<unsigned char>((v << 1) | bits[i * 8 + j]); }
                out[i] = static_cast<std::byte>(v);
            }
            return out;
        }

        template <std::size_t N, std::size_t M> std::array<int, N> permute(const std::array<int, M>& bits, const int (&table)[N]) noexcept
        {
            std::array<int, N> out{};

            for (std::size_t i = 0; i < N; ++i)
            {
                out[i] = bits[table[i] - 1];
            }
            return out;
        }

        BitArr32 des_feistel(const BitArr32& r, const std::array<std::byte, 6>& subkey) noexcept
        {
            const auto expanded = permute(r, kE);
            BitArr48 x{};

            for (int i = 0; i < 48; ++i)
            {
                const int byte_idx = i / 8, bit_idx = i % 8;
                const int key_bit = (static_cast<unsigned char>(subkey[byte_idx]) >> (7 - bit_idx)) & 1;
                x[i] = expanded[i] ^ key_bit;
            }
            BitArr32 s_out{};

            for (int i = 0; i < 8; ++i)
            {
                const int row = (x[i * 6 + 0] << 1) | x[i * 6 + 5];
                const int col = (x[i * 6 + 1] << 3) | (x[i * 6 + 2] << 2) | (x[i * 6 + 3] << 1) | x[i * 6 + 4];
                const int val = kSbox[i][row][col];

                for (int b = 0; b < 4; ++b)
                {
                    s_out[i * 4 + b] = (val >> (3 - b)) & 1;
                }
            }
            return permute(s_out, kP);
        }
    }

    ZeusDesCipher::ZeusDesCipher(std::span<const std::byte, 8> key)
    {
        auto key_bits = bytes_to_bits(key);
        auto pc1 = permute(key_bits, kPc1);
        std::array<int, 28> c{}, d{};
        std::copy(pc1.begin(), pc1.begin() + 28, c.begin());
        std::copy(pc1.begin() + 28, pc1.end(), d.begin());

        for (int round = 0; round < 16; ++round)
        {
            std::rotate(c.begin(), c.begin() + kShifts[round], c.end());
            std::rotate(d.begin(), d.begin() + kShifts[round], d.end());
            BitArr56 cd{};
            std::copy(c.begin(), c.end(), cd.begin());
            std::copy(d.begin(), d.end(), cd.begin() + 28);
            auto sk_bits = permute(cd, kPc2);

            for (int byte_idx = 0; byte_idx < 6; ++byte_idx)
            {
                unsigned char v = 0;
                for (int bit = 0; bit < 8; ++bit) { v = static_cast<unsigned char>((v << 1) | sk_bits[byte_idx * 8 + bit]); }
                subkeys_[round][byte_idx] = static_cast<std::byte>(v);
            }
        }
    }

    std::array<std::byte, 8> ZeusDesCipher::encrypt_block(std::span<const std::byte, 8> plaintext) const noexcept
    {
        auto bits = bytes_to_bits(plaintext);
        auto ip = permute(bits, kIp);
        BitArr32 l{}, r{};
        std::copy(ip.begin(), ip.begin() + 32, l.begin());
        std::copy(ip.begin() + 32, ip.end(), r.begin());

        for (int round = 0; round < 16; ++round)
        {
            auto f_out = des_feistel(r, subkeys_[round]);
            BitArr32 new_r{};

            for (int i = 0; i < 32; ++i)
            {
                new_r[i] = l[i] ^ f_out[i];
            }
            l = r;
            r = new_r;
        }
        BitArr64 pre{};
        std::copy(r.begin(), r.end(), pre.begin());
        std::copy(l.begin(), l.end(), pre.begin() + 32);
        auto out_bits = permute(pre, kFp);
        return bits_to_bytes(out_bits);
    }

    std::array<std::byte, 8> vnc_des_key_from_password(std::string_view password) noexcept
    {
        std::array<std::byte, 8> key{};

        for (std::size_t i = 0; i < 8; ++i)
        {
            const unsigned char src = (i < password.size()) ? static_cast<unsigned char>(password[i]) : 0;
            unsigned char rev = 0;

            for (int b = 0; b < 8; ++b)
            {
                rev = static_cast<unsigned char>((rev << 1) | ((src >> b) & 1));
            }
            key[i] = static_cast<std::byte>(rev);
        }
        return key;
    }
}





























































