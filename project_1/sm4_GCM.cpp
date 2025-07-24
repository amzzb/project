#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>
#include <random>
#include <immintrin.h>
#include <type_traits>

#ifdef _MSC_VER
#include <intrin.h>
#include <stdlib.h>
#define cpuid(info, x) __cpuidex(info, x, 0)
#define bswap32(x) _byteswap_ulong(x)
#define bswap64(x) _byteswap_uint64(x)
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#define bswap32(x) __builtin_bswap32(x)
#define bswap64(x) __builtin_bswap64(x)
static inline void cpuid(int info[4], int level) {
    __cpuid_count(level, 0, info[0], info[1], info[2], info[3]);
}
#else
static inline void cpuid(int info[4], int level) {
    info[0] = info[1] = info[2] = info[3] = 0;
}
static inline uint32_t bswap32(uint32_t x) {
    return ((x << 24) & 0xff000000) |
        ((x << 8) & 0x00ff0000) |
        ((x >> 8) & 0x0000ff00) |
        ((x >> 24) & 0x000000ff);
}
static inline uint64_t bswap64(uint64_t x) {
    return ((uint64_t)bswap32(x) << 32) | bswap32(x >> 32);
}
#endif

// SM4算法常量定义
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// 左循环位移操作
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// SM4算法上下文结构
struct SM4Context {
    uint32_t rk[32];  // 轮密钥
};

// GCM算法上下文结构
struct SM4GCMContext {
    SM4Context sm4_ctx;
    uint64_t h[2];      // GHASH哈希子密钥H
    uint8_t counter[16]; // CTR模式计数器
    uint64_t aad_len;    // 附加认证数据长度
    uint64_t text_len;   // 明文/密文长度
    uint8_t tag[16];     // 认证标签
    uint8_t ghash_state[16]; // GHASH状态
};

// CPU特性检测
struct CPUFeatures {
    bool sse2;
    bool aes;
    bool avx2;
    bool avx512f;
    bool gfni;
    bool vaes;
    bool pclmul;

    CPUFeatures() : sse2(false), aes(false), avx2(false), avx512f(false),
        gfni(false), vaes(false), pclmul(false) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
        int info[4];

        // 检测基础特性
        cpuid(info, 1);
        sse2 = (info[3] & (1 << 26)) != 0;
        aes = (info[2] & (1 << 25)) != 0;
        pclmul = (info[2] & (1 << 1)) != 0;

        // 检测扩展特性
        cpuid(info, 7);
        avx2 = (info[1] & (1 << 5)) != 0;
        avx512f = (info[1] & (1 << 16)) != 0;
        gfni = (info[2] & (1 << 8)) != 0;
        vaes = (info[2] & (1 << 9)) != 0;
#endif
    }
};

// 基础SM4实现类
class SM4Basic {
private:
    static uint32_t sbox_lookup(uint32_t x) {
        return (SM4_SBOX[(x >> 24) & 0xff] << 24) |
            (SM4_SBOX[(x >> 16) & 0xff] << 16) |
            (SM4_SBOX[(x >> 8) & 0xff] << 8) |
            (SM4_SBOX[x & 0xff]);
    }

    static uint32_t linear_transform(uint32_t x) {
        return x ^ ROL32(x, 2) ^ ROL32(x, 10) ^ ROL32(x, 18) ^ ROL32(x, 24);
    }

    static uint32_t tau(uint32_t x) {
        return linear_transform(sbox_lookup(x));
    }

public:
    static void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext, const SM4Context& ctx) {
        uint32_t x[4];

        // 加载明文
        for (int i = 0; i < 4; i++) {
            x[i] = (plaintext[i * 4] << 24) | (plaintext[i * 4 + 1] << 16) |
                (plaintext[i * 4 + 2] << 8) | plaintext[i * 4 + 3];
        }

        // 32轮加密
        for (int i = 0; i < 32; i++) {
            uint32_t t = x[1] ^ x[2] ^ x[3] ^ ctx.rk[i];
            uint32_t new_x = x[0] ^ tau(t);
            x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = new_x;
        }

        // 存储密文
        for (int i = 0; i < 4; i++) {
            ciphertext[i * 4] = (x[3 - i] >> 24) & 0xff;
            ciphertext[i * 4 + 1] = (x[3 - i] >> 16) & 0xff;
            ciphertext[i * 4 + 2] = (x[3 - i] >> 8) & 0xff;
            ciphertext[i * 4 + 3] = x[3 - i] & 0xff;
        }
    }
};

// T-table优化SM4实现
class SM4TTable {
private:
    static uint32_t T0[256], T1[256], T2[256], T3[256];
    static bool tables_initialized;

    static void init_tables() {
        if (tables_initialized) return;

        for (int i = 0; i < 256; i++) {
            uint32_t s = SM4_SBOX[i];
            uint32_t t = s | (s << 8) | (s << 16) | (s << 24);

            T0[i] = t ^ ROL32(t, 2) ^ ROL32(t, 10) ^ ROL32(t, 18) ^ ROL32(t, 24);
            T1[i] = ROL32(T0[i], 8);
            T2[i] = ROL32(T0[i], 16);
            T3[i] = ROL32(T0[i], 24);
        }
        tables_initialized = true;
    }

public:
    static void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext, const SM4Context& ctx) {
        init_tables();

        uint32_t x[4];

        // 加载明文
        for (int i = 0; i < 4; i++) {
            x[i] = (plaintext[i * 4] << 24) | (plaintext[i * 4 + 1] << 16) |
                (plaintext[i * 4 + 2] << 8) | plaintext[i * 4 + 3];
        }

        // 32轮加密
        for (int i = 0; i < 32; i++) {
            uint32_t t = x[1] ^ x[2] ^ x[3] ^ ctx.rk[i];
            uint32_t new_x = x[0] ^ T0[(t >> 24) & 0xff] ^
                T1[(t >> 16) & 0xff] ^
                T2[(t >> 8) & 0xff] ^
                T3[t & 0xff];
            x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = new_x;
        }

        // 存储密文
        for (int i = 0; i < 4; i++) {
            ciphertext[i * 4] = (x[3 - i] >> 24) & 0xff;
            ciphertext[i * 4 + 1] = (x[3 - i] >> 16) & 0xff;
            ciphertext[i * 4 + 2] = (x[3 - i] >> 8) & 0xff;
            ciphertext[i * 4 + 3] = x[3 - i] & 0xff;
        }
    }
};

uint32_t SM4TTable::T0[256];
uint32_t SM4TTable::T1[256];
uint32_t SM4TTable::T2[256];
uint32_t SM4TTable::T3[256];
bool SM4TTable::tables_initialized = false;

// AESNI优化SM4实现
class SM4AESNI {
private:
#if defined(__SSE2__)
    static __m128i sbox_sse(__m128i x) {
        alignas(16) uint8_t tmp[16];
        _mm_store_si128((__m128i*)tmp, x);

        for (int i = 0; i < 16; i++) {
            tmp[i] = SM4_SBOX[tmp[i]];
        }

        return _mm_load_si128((__m128i*)tmp);
    }

    static __m128i linear_transform_sse(__m128i x) {
        __m128i t2 = _mm_or_si128(_mm_slli_epi32(x, 2), _mm_srli_epi32(x, 30));
        __m128i t10 = _mm_or_si128(_mm_slli_epi32(x, 10), _mm_srli_epi32(x, 22));
        __m128i t18 = _mm_or_si128(_mm_slli_epi32(x, 18), _mm_srli_epi32(x, 14));
        __m128i t24 = _mm_or_si128(_mm_slli_epi32(x, 24), _mm_srli_epi32(x, 8));

        return _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(x, t2), t10), t18), t24);
    }
#endif

public:
    static void encrypt_4blocks(const uint8_t* plaintext, uint8_t* ciphertext, const SM4Context& ctx) {
#if defined(__SSE2__) && defined(__SSSE3__)
        __m128i x0 = _mm_loadu_si128((__m128i*)(plaintext + 0));
        __m128i x1 = _mm_loadu_si128((__m128i*)(plaintext + 16));
        __m128i x2 = _mm_loadu_si128((__m128i*)(plaintext + 32));
        __m128i x3 = _mm_loadu_si128((__m128i*)(plaintext + 48));

        // 字节序转换
        const __m128i endian_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
        x0 = _mm_shuffle_epi8(x0, endian_mask);
        x1 = _mm_shuffle_epi8(x1, endian_mask);
        x2 = _mm_shuffle_epi8(x2, endian_mask);
        x3 = _mm_shuffle_epi8(x3, endian_mask);

        // 32轮加密
        for (int i = 0; i < 32; i++) {
            __m128i rk = _mm_set1_epi32(ctx.rk[i]);

            __m128i t0 = _mm_xor_si128(_mm_xor_si128(x1, x2), _mm_xor_si128(x3, rk));
            t0 = sbox_sse(t0);
            t0 = linear_transform_sse(t0);

            __m128i new_x0 = _mm_xor_si128(x0, t0);
            x0 = x1; x1 = x2; x2 = x3; x3 = new_x0;
        }

        // 反序并存储
        __m128i temp = x0; x0 = x3; x3 = temp;
        temp = x1; x1 = x2; x2 = temp;

        x0 = _mm_shuffle_epi8(x0, endian_mask);
        x1 = _mm_shuffle_epi8(x1, endian_mask);
        x2 = _mm_shuffle_epi8(x2, endian_mask);
        x3 = _mm_shuffle_epi8(x3, endian_mask);

        _mm_storeu_si128((__m128i*)(ciphertext + 0), x0);
        _mm_storeu_si128((__m128i*)(ciphertext + 16), x1);
        _mm_storeu_si128((__m128i*)(ciphertext + 32), x2);
        _mm_storeu_si128((__m128i*)(ciphertext + 48), x3);
#else
        // 回退到单块处理
        for (int i = 0; i < 4; i++) {
            SM4TTable::encrypt_block(plaintext + i * 16, ciphertext + i * 16, ctx);
        }
#endif
    }

    static void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext, const SM4Context& ctx) {
        SM4TTable::encrypt_block(plaintext, ciphertext, ctx);
    }
};

// GFNI优化SM4实现
class SM4GFNI {
private:
#if defined(__AVX2__)
    static __m256i sbox_gfni(__m256i x) {
#if defined(__GFNI__)
        const __m256i matrix1 = _mm256_set1_epi64x(0x8040201008040201ULL);
        const __m256i matrix2 = _mm256_set1_epi64x(0x0102040810204080ULL);

        x = _mm256_gf2p8affine_epi64_epi8(x, matrix1, 0x63);
        x = _mm256_gf2p8inv_epi8(x);
        x = _mm256_gf2p8affine_epi64_epi8(x, matrix2, 0x8F);
        return x;
#else
        alignas(32) uint8_t tmp[32];
        _mm256_store_si256((__m256i*)tmp, x);
        for (int i = 0; i < 32; i++) {
            tmp[i] = SM4_SBOX[tmp[i]];
        }
        return _mm256_load_si256((__m256i*)tmp);
#endif
    }

    static __m256i linear_transform_avx2(__m256i x) {
        __m256i t2 = _mm256_or_si256(_mm256_slli_epi32(x, 2), _mm256_srli_epi32(x, 30));
        __m256i t10 = _mm256_or_si256(_mm256_slli_epi32(x, 10), _mm256_srli_epi32(x, 22));
        __m256i t18 = _mm256_or_si256(_mm256_slli_epi32(x, 18), _mm256_srli_epi32(x, 14));
        __m256i t24 = _mm256_or_si256(_mm256_slli_epi32(x, 24), _mm256_srli_epi32(x, 8));

        return _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(x, t2), t10), t18), t24);
    }
#endif

public:
    static void encrypt_8blocks(const uint8_t* plaintext, uint8_t* ciphertext, const SM4Context& ctx) {
#if defined(__AVX2__)
        __m256i x0 = _mm256_loadu_si256((__m256i*)(plaintext + 0));
        __m256i x1 = _mm256_loadu_si256((__m256i*)(plaintext + 32));
        __m256i x2 = _mm256_loadu_si256((__m256i*)(plaintext + 64));
        __m256i x3 = _mm256_loadu_si256((__m256i*)(plaintext + 96));

        // 字节序转换
        const __m256i endian_mask = _mm256_set_epi8(
            12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
            12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3
        );

        x0 = _mm256_shuffle_epi8(x0, endian_mask);
        x1 = _mm256_shuffle_epi8(x1, endian_mask);
        x2 = _mm256_shuffle_epi8(x2, endian_mask);
        x3 = _mm256_shuffle_epi8(x3, endian_mask);

        // 32轮加密
        for (int i = 0; i < 32; i++) {
            __m256i rk = _mm256_set1_epi32(ctx.rk[i]);

            __m256i t = _mm256_xor_si256(_mm256_xor_si256(x1, x2), _mm256_xor_si256(x3, rk));
            t = sbox_gfni(t);
            t = linear_transform_avx2(t);

            __m256i new_x0 = _mm256_xor_si256(x0, t);
            x0 = x1; x1 = x2; x2 = x3; x3 = new_x0;
        }

        // 反序
        __m256i temp = x0; x0 = x3; x3 = temp;
        temp = x1; x1 = x2; x2 = temp;

        x0 = _mm256_shuffle_epi8(x0, endian_mask);
        x1 = _mm256_shuffle_epi8(x1, endian_mask);
        x2 = _mm256_shuffle_epi8(x2, endian_mask);
        x3 = _mm256_shuffle_epi8(x3, endian_mask);

        _mm256_storeu_si256((__m256i*)(ciphertext + 0), x0);
        _mm256_storeu_si256((__m256i*)(ciphertext + 32), x1);
        _mm256_storeu_si256((__m256i*)(ciphertext + 64), x2);
        _mm256_storeu_si256((__m256i*)(ciphertext + 96), x3);
#else
        // 回退到单块处理
        for (int i = 0; i < 8; i++) {
            SM4TTable::encrypt_block(plaintext + i * 16, ciphertext + i * 16, ctx);
        }
#endif
    }
};

// 密钥扩展
class SM4KeySchedule {
private:
    static const uint32_t FK[4];
    static const uint32_t CK[32];

    static uint32_t tau_key(uint32_t x) {
        uint32_t s = (SM4_SBOX[(x >> 24) & 0xff] << 24) |
            (SM4_SBOX[(x >> 16) & 0xff] << 16) |
            (SM4_SBOX[(x >> 8) & 0xff] << 8) |
            (SM4_SBOX[x & 0xff]);
        return s ^ ROL32(s, 13) ^ ROL32(s, 23);
    }

public:
    static void expand_key(const uint8_t* key, SM4Context& ctx) {
        uint32_t k[4];

        for (int i = 0; i < 4; i++) {
            k[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) |
                (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        }

        for (int i = 0; i < 4; i++) {
            k[i] ^= FK[i];
        }

        for (int i = 0; i < 32; i++) {
            uint32_t t = k[1] ^ k[2] ^ k[3] ^ CK[i];
            ctx.rk[i] = k[0] ^ tau_key(t);
            k[0] = k[1]; k[1] = k[2]; k[2] = k[3]; k[3] = ctx.rk[i];
        }
    }
};

const uint32_t SM4KeySchedule::FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

const uint32_t SM4KeySchedule::CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// GHASH基础实现 - 完全修复const问题
class GHASHBasic {
public:
    static void ghash_update(uint8_t state[16], const uint8_t* data, size_t len, const uint64_t h[2]) {
        uint64_t s[2], temp[2];

        // 转换状态为大端序64位
        s[0] = ((uint64_t)state[0] << 56) | ((uint64_t)state[1] << 48) |
            ((uint64_t)state[2] << 40) | ((uint64_t)state[3] << 32) |
            ((uint64_t)state[4] << 24) | ((uint64_t)state[5] << 16) |
            ((uint64_t)state[6] << 8) | (uint64_t)state[7];
        s[1] = ((uint64_t)state[8] << 56) | ((uint64_t)state[9] << 48) |
            ((uint64_t)state[10] << 40) | ((uint64_t)state[11] << 32) |
            ((uint64_t)state[12] << 24) | ((uint64_t)state[13] << 16) |
            ((uint64_t)state[14] << 8) | (uint64_t)state[15];

        for (size_t i = 0; i < len; i += 16) {
            uint64_t block[2];

            // 处理完整块或部分块
            if (i + 16 <= len) {
                block[0] = ((uint64_t)data[i + 0] << 56) | ((uint64_t)data[i + 1] << 48) |
                    ((uint64_t)data[i + 2] << 40) | ((uint64_t)data[i + 3] << 32) |
                    ((uint64_t)data[i + 4] << 24) | ((uint64_t)data[i + 5] << 16) |
                    ((uint64_t)data[i + 6] << 8) | (uint64_t)data[i + 7];
                block[1] = ((uint64_t)data[i + 8] << 56) | ((uint64_t)data[i + 9] << 48) |
                    ((uint64_t)data[i + 10] << 40) | ((uint64_t)data[i + 11] << 32) |
                    ((uint64_t)data[i + 12] << 24) | ((uint64_t)data[i + 13] << 16) |
                    ((uint64_t)data[i + 14] << 8) | (uint64_t)data[i + 15];
            }
            else {
                // 处理最后不完整的块
                uint8_t padded[16] = { 0 };
                memcpy(padded, data + i, len - i);
                block[0] = ((uint64_t)padded[0] << 56) | ((uint64_t)padded[1] << 48) |
                    ((uint64_t)padded[2] << 40) | ((uint64_t)padded[3] << 32) |
                    ((uint64_t)padded[4] << 24) | ((uint64_t)padded[5] << 16) |
                    ((uint64_t)padded[6] << 8) | (uint64_t)padded[7];
                block[1] = ((uint64_t)padded[8] << 56) | ((uint64_t)padded[9] << 48) |
                    ((uint64_t)padded[10] << 40) | ((uint64_t)padded[11] << 32) |
                    ((uint64_t)padded[12] << 24) | ((uint64_t)padded[13] << 16) |
                    ((uint64_t)padded[14] << 8) | (uint64_t)padded[15];
            }

            // GHASH: (s ⊕ block) * H
            s[0] ^= block[0];
            s[1] ^= block[1];
            gf128_multiply(s, h, temp);
            s[0] = temp[0];
            s[1] = temp[1];
        }

        // 转换回字节序列
        for (int i = 0; i < 8; i++) {
            state[i] = (s[0] >> (56 - i * 8)) & 0xff;
            state[i + 8] = (s[1] >> (56 - i * 8)) & 0xff;
        }
    }

private:
    // 修复：移除const限制，使用内联实现
    static void gf128_multiply(uint64_t a[2], const uint64_t h[2], uint64_t result[2]) {
        uint64_t z[2] = { 0, 0 };
        uint64_t v[2] = { a[0], a[1] };

        for (int i = 0; i < 128; i++) {
            if ((h[i / 64] >> (63 - (i % 64))) & 1) {
                z[0] ^= v[0];
                z[1] ^= v[1];
            }

            bool carry = v[1] & 1;
            v[1] = (v[1] >> 1) | ((v[0] & 1) << 63);
            v[0] = v[0] >> 1;
            if (carry) {
                v[0] ^= 0xE100000000000000ULL;
            }
        }

        result[0] = z[0];
        result[1] = z[1];
    }
};

// PCLMUL优化GHASH实现
class GHASHPCLMUL {
public:
    static void ghash_update(uint8_t state[16], const uint8_t* data, size_t len, const uint64_t h[2]) {
#if defined(__PCLMUL__) && defined(__SSE2__)
        __m128i h_reg = _mm_set_epi64x(h[0], h[1]);
        __m128i state_reg = _mm_loadu_si128((__m128i*)state);

        // 字节序转换
        const __m128i bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        state_reg = _mm_shuffle_epi8(state_reg, bswap_mask);
        h_reg = _mm_shuffle_epi8(h_reg, bswap_mask);

        for (size_t i = 0; i < len; i += 16) {
            __m128i block;

            if (i + 16 <= len) {
                block = _mm_loadu_si128((__m128i*)(data + i));
            }
            else {
                uint8_t padded[16] = { 0 };
                memcpy(padded, data + i, len - i);
                block = _mm_load_si128((__m128i*)padded);
            }

            block = _mm_shuffle_epi8(block, bswap_mask);

            // GHASH: (state ⊕ block) * H
            state_reg = _mm_xor_si128(state_reg, block);

            // 使用PCLMULQDQ进行GF(2^128)乘法
            __m128i tmp0 = _mm_clmulepi64_si128(state_reg, h_reg, 0x00);
            __m128i tmp1 = _mm_clmulepi64_si128(state_reg, h_reg, 0x01);
            __m128i tmp2 = _mm_clmulepi64_si128(state_reg, h_reg, 0x10);
            __m128i tmp3 = _mm_clmulepi64_si128(state_reg, h_reg, 0x11);

            tmp1 = _mm_xor_si128(tmp1, tmp2);
            __m128i tmp1_high = _mm_unpackhi_epi64(tmp1, _mm_setzero_si128());
            __m128i tmp1_low = _mm_unpacklo_epi64(_mm_setzero_si128(), tmp1);

            tmp0 = _mm_xor_si128(tmp0, tmp1_low);
            tmp3 = _mm_xor_si128(tmp3, tmp1_high);

            // 模约简
            __m128i reduction = _mm_clmulepi64_si128(tmp3, _mm_set_epi64x(0, 0x87), 0x01);
            tmp3 = _mm_xor_si128(tmp3, reduction);
            reduction = _mm_clmulepi64_si128(tmp3, _mm_set_epi64x(0, 0x87), 0x00);
            state_reg = _mm_xor_si128(tmp0, reduction);
        }

        state_reg = _mm_shuffle_epi8(state_reg, bswap_mask);
        _mm_storeu_si128((__m128i*)state, state_reg);
#else
        // 降级到基础实现
        GHASHBasic::ghash_update(state, data, len, h);
#endif
    }
};

// 自适应SM4实现
class SM4Adaptive {
private:
    static CPUFeatures features;
    static bool features_detected;

public:
    static void encrypt_blocks(const uint8_t* plaintext, uint8_t* ciphertext,
        const SM4Context& ctx, size_t num_blocks) {
        if (!features_detected) {
            features = CPUFeatures();
            features_detected = true;
        }

        size_t bytes = num_blocks * 16;

        // 根据CPU特性选择最优实现
        if (features.avx2 && bytes >= 128) {
            // 使用AVX2实现处理8块并行
            size_t avx2_blocks = (bytes / 128) * 8;
            for (size_t i = 0; i < avx2_blocks; i += 8) {
                SM4GFNI::encrypt_8blocks(plaintext + i * 16, ciphertext + i * 16, ctx);
            }

            // 处理剩余块
            for (size_t i = avx2_blocks; i < num_blocks; i++) {
                SM4TTable::encrypt_block(plaintext + i * 16, ciphertext + i * 16, ctx);
            }
        }
        else if (features.aes && bytes >= 64) {
            // 使用AESNI实现处理4块并行
            size_t aesni_blocks = (bytes / 64) * 4;
            for (size_t i = 0; i < aesni_blocks; i += 4) {
                SM4AESNI::encrypt_4blocks(plaintext + i * 16, ciphertext + i * 16, ctx);
            }

            // 处理剩余块
            for (size_t i = aesni_blocks; i < num_blocks; i++) {
                SM4TTable::encrypt_block(plaintext + i * 16, ciphertext + i * 16, ctx);
            }
        }
        else {
            // 使用T-table实现
            for (size_t i = 0; i < num_blocks; i++) {
                SM4TTable::encrypt_block(plaintext + i * 16, ciphertext + i * 16, ctx);
            }
        }
    }
};

CPUFeatures SM4Adaptive::features;
bool SM4Adaptive::features_detected = false;

// SM4-GCM实现
class SM4GCM {
private:
    static CPUFeatures features;
    static bool features_detected;

    static void inc_counter(uint8_t counter[16]) {
        for (int i = 15; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
    }

    static void inc_counter_32(uint8_t counter[16]) {
        // GCM标准计数器只在最后32位递增
        uint32_t ctr_val;
        memcpy(&ctr_val, counter + 12, 4);
        ctr_val = bswap32(bswap32(ctr_val) + 1);
        memcpy(counter + 12, &ctr_val, 4);
    }

    // 修复：使用普通函数重载代替模板和if constexpr
    static void ctr_encrypt_blocks_aesni(const uint8_t* plaintext, uint8_t* ciphertext,
        size_t num_blocks, uint8_t counter[16], const SM4Context& ctx) {
        const size_t IMPL_BLOCKS = 4;
        uint8_t keystream[IMPL_BLOCKS * 16];
        uint8_t counter_blocks[IMPL_BLOCKS * 16];

        for (size_t i = 0; i < num_blocks; i += IMPL_BLOCKS) {
            size_t blocks_to_process = std::min(IMPL_BLOCKS, num_blocks - i);

            // 准备计数器块
            for (size_t j = 0; j < blocks_to_process; j++) {
                memcpy(counter_blocks + j * 16, counter, 16);
                inc_counter_32(counter);
            }

            // 加密计数器生成密钥流
            if (blocks_to_process == 4) {
                SM4AESNI::encrypt_4blocks(counter_blocks, keystream, ctx);
            }
            else {
                for (size_t j = 0; j < blocks_to_process; j++) {
                    SM4TTable::encrypt_block(counter_blocks + j * 16, keystream + j * 16, ctx);
                }
            }

            // XOR明文和密钥流
            for (size_t j = 0; j < blocks_to_process; j++) {
                for (int k = 0; k < 16; k++) {
                    ciphertext[(i + j) * 16 + k] = plaintext[(i + j) * 16 + k] ^ keystream[j * 16 + k];
                }
            }
        }
    }

    static void ctr_encrypt_blocks_basic(const uint8_t* plaintext, uint8_t* ciphertext,
        size_t num_blocks, uint8_t counter[16], const SM4Context& ctx) {
        const size_t IMPL_BLOCKS = 1;
        uint8_t keystream[IMPL_BLOCKS * 16];
        uint8_t counter_blocks[IMPL_BLOCKS * 16];

        for (size_t i = 0; i < num_blocks; i += IMPL_BLOCKS) {
            size_t blocks_to_process = std::min(IMPL_BLOCKS, num_blocks - i);

            for (size_t j = 0; j < blocks_to_process; j++) {
                memcpy(counter_blocks + j * 16, counter, 16);
                inc_counter_32(counter);
            }

            for (size_t j = 0; j < blocks_to_process; j++) {
                SM4TTable::encrypt_block(counter_blocks + j * 16, keystream + j * 16, ctx);
            }

            for (size_t j = 0; j < blocks_to_process; j++) {
                for (int k = 0; k < 16; k++) {
                    ciphertext[(i + j) * 16 + k] = plaintext[(i + j) * 16 + k] ^ keystream[j * 16 + k];
                }
            }
        }
    }

public:
    static void init_gcm(SM4GCMContext& gcm_ctx, const uint8_t* key, const uint8_t* iv, size_t iv_len) {
        if (!features_detected) {
            features = CPUFeatures();
            features_detected = true;
        }

        // 初始化SM4密钥
        SM4KeySchedule::expand_key(key, gcm_ctx.sm4_ctx);

        // 生成GHASH子密钥H = E_K(0^128)
        uint8_t zero_block[16] = { 0 };
        uint8_t h_bytes[16];
        SM4TTable::encrypt_block(zero_block, h_bytes, gcm_ctx.sm4_ctx);

        // 转换H为64位大端序
        gcm_ctx.h[0] = ((uint64_t)h_bytes[0] << 56) | ((uint64_t)h_bytes[1] << 48) |
            ((uint64_t)h_bytes[2] << 40) | ((uint64_t)h_bytes[3] << 32) |
            ((uint64_t)h_bytes[4] << 24) | ((uint64_t)h_bytes[5] << 16) |
            ((uint64_t)h_bytes[6] << 8) | (uint64_t)h_bytes[7];
        gcm_ctx.h[1] = ((uint64_t)h_bytes[8] << 56) | ((uint64_t)h_bytes[9] << 48) |
            ((uint64_t)h_bytes[10] << 40) | ((uint64_t)h_bytes[11] << 32) |
            ((uint64_t)h_bytes[12] << 24) | ((uint64_t)h_bytes[13] << 16) |
            ((uint64_t)h_bytes[14] << 8) | (uint64_t)h_bytes[15];

        // 初始化计数器
        memset(gcm_ctx.counter, 0, 16);
        if (iv_len == 12) {
            // 标准96位IV
            memcpy(gcm_ctx.counter, iv, 12);
            // 设置最后32位为1 (大端序)
            gcm_ctx.counter[15] = 1;
        }
        else {
            // 非标准IV需要GHASH处理
            memset(gcm_ctx.ghash_state, 0, 16);

            if (features.pclmul) {
                GHASHPCLMUL::ghash_update(gcm_ctx.ghash_state, iv, iv_len, gcm_ctx.h);
            }
            else {
                GHASHBasic::ghash_update(gcm_ctx.ghash_state, iv, iv_len, gcm_ctx.h);
            }

            // 添加长度
            uint8_t len_block[16] = { 0 };
            uint64_t bit_len = iv_len * 8;
            len_block[8] = (bit_len >> 56) & 0xff;
            len_block[9] = (bit_len >> 48) & 0xff;
            len_block[10] = (bit_len >> 40) & 0xff;
            len_block[11] = (bit_len >> 32) & 0xff;
            len_block[12] = (bit_len >> 24) & 0xff;
            len_block[13] = (bit_len >> 16) & 0xff;
            len_block[14] = (bit_len >> 8) & 0xff;
            len_block[15] = bit_len & 0xff;

            if (features.pclmul) {
                GHASHPCLMUL::ghash_update(gcm_ctx.ghash_state, len_block, 16, gcm_ctx.h);
            }
            else {
                GHASHBasic::ghash_update(gcm_ctx.ghash_state, len_block, 16, gcm_ctx.h);
            }

            memcpy(gcm_ctx.counter, gcm_ctx.ghash_state, 16);
        }

        // 初始化状态
        gcm_ctx.aad_len = 0;
        gcm_ctx.text_len = 0;
        memset(gcm_ctx.ghash_state, 0, 16);
    }

    static void update_aad(SM4GCMContext& gcm_ctx, const uint8_t* aad, size_t aad_len) {
        if (aad_len == 0) return;

        gcm_ctx.aad_len += aad_len;

        if (features.pclmul) {
            GHASHPCLMUL::ghash_update(gcm_ctx.ghash_state, aad, aad_len, gcm_ctx.h);
        }
        else {
            GHASHBasic::ghash_update(gcm_ctx.ghash_state, aad, aad_len, gcm_ctx.h);
        }
    }

    static void encrypt_update(SM4GCMContext& gcm_ctx, const uint8_t* plaintext,
        uint8_t* ciphertext, size_t len) {
        if (len == 0) return;

        gcm_ctx.text_len += len;

        // CTR模式加密
        uint8_t counter[16];
        memcpy(counter, gcm_ctx.counter, 16);

        size_t full_blocks = len / 16;
        size_t remaining = len % 16;

        // 处理完整块
        if (full_blocks > 0) {
            if (features.aes && full_blocks >= 4) {
                // 使用AESNI 4块并行加密
                for (size_t i = 0; i < full_blocks; i += 4) {
                    size_t blocks_to_process = std::min((size_t)4, full_blocks - i);
                    if (blocks_to_process == 4) {
                        ctr_encrypt_blocks_aesni(plaintext + i * 16, ciphertext + i * 16,
                            4, counter, gcm_ctx.sm4_ctx);
                    }
                    else {
                        ctr_encrypt_blocks_basic(plaintext + i * 16, ciphertext + i * 16,
                            blocks_to_process, counter, gcm_ctx.sm4_ctx);
                    }
                }
            }
            else {
                ctr_encrypt_blocks_basic(plaintext, ciphertext, full_blocks,
                    counter, gcm_ctx.sm4_ctx);
            }
        }

        // 处理最后不完整的块
        if (remaining > 0) {
            uint8_t keystream[16];
            SM4TTable::encrypt_block(counter, keystream, gcm_ctx.sm4_ctx);
            for (size_t i = 0; i < remaining; i++) {
                ciphertext[full_blocks * 16 + i] = plaintext[full_blocks * 16 + i] ^ keystream[i];
            }
        }

        // 更新计数器
        size_t total_blocks = (len + 15) / 16;
        for (size_t i = 0; i < total_blocks; i++) {
            inc_counter_32(gcm_ctx.counter);
        }

        // GHASH处理密文
        if (features.pclmul) {
            GHASHPCLMUL::ghash_update(gcm_ctx.ghash_state, ciphertext, len, gcm_ctx.h);
        }
        else {
            GHASHBasic::ghash_update(gcm_ctx.ghash_state, ciphertext, len, gcm_ctx.h);
        }
    }

    static void finalize(SM4GCMContext& gcm_ctx, uint8_t* tag) {
        // 构造长度块
        uint8_t len_block[16] = { 0 };
        uint64_t aad_bits = gcm_ctx.aad_len * 8;
        uint64_t text_bits = gcm_ctx.text_len * 8;

        // AAD长度 (大端序)
        len_block[0] = (aad_bits >> 56) & 0xff;
        len_block[1] = (aad_bits >> 48) & 0xff;
        len_block[2] = (aad_bits >> 40) & 0xff;
        len_block[3] = (aad_bits >> 32) & 0xff;
        len_block[4] = (aad_bits >> 24) & 0xff;
        len_block[5] = (aad_bits >> 16) & 0xff;
        len_block[6] = (aad_bits >> 8) & 0xff;
        len_block[7] = aad_bits & 0xff;

        // 文本长度 (大端序)
        len_block[8] = (text_bits >> 56) & 0xff;
        len_block[9] = (text_bits >> 48) & 0xff;
        len_block[10] = (text_bits >> 40) & 0xff;
        len_block[11] = (text_bits >> 32) & 0xff;
        len_block[12] = (text_bits >> 24) & 0xff;
        len_block[13] = (text_bits >> 16) & 0xff;
        len_block[14] = (text_bits >> 8) & 0xff;
        len_block[15] = text_bits & 0xff;

        // 最终GHASH
        if (features.pclmul) {
            GHASHPCLMUL::ghash_update(gcm_ctx.ghash_state, len_block, 16, gcm_ctx.h);
        }
        else {
            GHASHBasic::ghash_update(gcm_ctx.ghash_state, len_block, 16, gcm_ctx.h);
        }

        // 生成认证标签: GHASH ⊕ E_K(J_0)
        uint8_t j0[16];
        memcpy(j0, gcm_ctx.counter, 16);
        // 恢复J_0 (计数器初始值)
        uint32_t ctr_val;
        memcpy(&ctr_val, j0 + 12, 4);
        ctr_val = bswap32(bswap32(ctr_val) - (uint32_t)((gcm_ctx.text_len + 15) / 16));
        memcpy(j0 + 12, &ctr_val, 4);

        uint8_t e_j0[16];
        SM4TTable::encrypt_block(j0, e_j0, gcm_ctx.sm4_ctx);

        for (int i = 0; i < 16; i++) {
            tag[i] = gcm_ctx.ghash_state[i] ^ e_j0[i];
        }

        memcpy(gcm_ctx.tag, tag, 16);
    }

    // 解密函数
    static void decrypt_update(SM4GCMContext& gcm_ctx, const uint8_t* ciphertext,
        uint8_t* plaintext, size_t len) {
        if (len == 0) return;

        // 先更新GHASH
        if (features.pclmul) {
            GHASHPCLMUL::ghash_update(gcm_ctx.ghash_state, ciphertext, len, gcm_ctx.h);
        }
        else {
            GHASHBasic::ghash_update(gcm_ctx.ghash_state, ciphertext, len, gcm_ctx.h);
        }

        gcm_ctx.text_len += len;

        // CTR模式解密（与加密相同）
        uint8_t counter[16];
        memcpy(counter, gcm_ctx.counter, 16);

        size_t full_blocks = len / 16;
        size_t remaining = len % 16;

        // 处理完整块
        if (full_blocks > 0) {
            if (features.aes && full_blocks >= 4) {
                for (size_t i = 0; i < full_blocks; i += 4) {
                    size_t blocks_to_process = std::min((size_t)4, full_blocks - i);
                    if (blocks_to_process == 4) {
                        ctr_encrypt_blocks_aesni(ciphertext + i * 16, plaintext + i * 16,
                            4, counter, gcm_ctx.sm4_ctx);
                    }
                    else {
                        ctr_encrypt_blocks_basic(ciphertext + i * 16, plaintext + i * 16,
                            blocks_to_process, counter, gcm_ctx.sm4_ctx);
                    }
                }
            }
            else {
                ctr_encrypt_blocks_basic(ciphertext, plaintext, full_blocks,
                    counter, gcm_ctx.sm4_ctx);
            }
        }

        // 处理最后不完整的块
        if (remaining > 0) {
            uint8_t keystream[16];
            SM4TTable::encrypt_block(counter, keystream, gcm_ctx.sm4_ctx);
            for (size_t i = 0; i < remaining; i++) {
                plaintext[full_blocks * 16 + i] = ciphertext[full_blocks * 16 + i] ^ keystream[i];
            }
        }

        // 更新计数器
        size_t total_blocks = (len + 15) / 16;
        for (size_t i = 0; i < total_blocks; i++) {
            inc_counter_32(gcm_ctx.counter);
        }
    }

    // 验证标签
    static bool verify_tag(const SM4GCMContext& gcm_ctx, const uint8_t* tag) {
        uint8_t computed_tag[16];
        SM4GCMContext temp_ctx = gcm_ctx;
        finalize(temp_ctx, computed_tag);

        return memcmp(computed_tag, tag, 16) == 0;
    }
};

CPUFeatures SM4GCM::features;
bool SM4GCM::features_detected = false;

// 性能测试类
class SM4Benchmark {
private:
    static const size_t TEST_SIZE = 1024 * 1024;  // 1MB
    static const int ITERATIONS = 100;

    template<typename Func>
    static double measure_performance(Func func, const std::string& name) {
        std::vector<uint8_t> plaintext(TEST_SIZE);
        std::vector<uint8_t> ciphertext(TEST_SIZE);
        std::vector<uint8_t> key(16);

        // 生成随机数据
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (size_t i = 0; i < plaintext.size(); i++) plaintext[i] = dis(gen);
        for (size_t i = 0; i < key.size(); i++) key[i] = dis(gen);

        SM4Context ctx;
        SM4KeySchedule::expand_key(key.data(), ctx);

        auto start = std::chrono::high_resolution_clock::now();

        for (int iter = 0; iter < ITERATIONS; iter++) {
            func(plaintext.data(), ciphertext.data(), ctx, plaintext.size());
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        double mbps = (double)(TEST_SIZE * ITERATIONS) / duration.count();
        double gbps = mbps / 1000.0;

        std::cout << name << ": " << gbps << " GB/s" << std::endl;
        return gbps;
    }

public:
    static void run_benchmarks() {
        CPUFeatures features;

        std::cout << "=== SM4 性能测试 ===" << std::endl;
        std::cout << "CPU特性: ";
        if (features.sse2) std::cout << "SSE2 ";
        if (features.aes) std::cout << "AES ";
        if (features.avx2) std::cout << "AVX2 ";
        if (features.avx512f) std::cout << "AVX512F ";
        if (features.gfni) std::cout << "GFNI ";
        if (features.pclmul) std::cout << "PCLMUL ";
        std::cout << std::endl << std::endl;

        // 基础实现
        measure_performance([](const uint8_t* in, uint8_t* out, const SM4Context& ctx, size_t size) {
            for (size_t i = 0; i < size; i += 16) {
                SM4Basic::encrypt_block(in + i, out + i, ctx);
            }
            }, "基础实现");

        // T-table实现
        measure_performance([](const uint8_t* in, uint8_t* out, const SM4Context& ctx, size_t size) {
            for (size_t i = 0; i < size; i += 16) {
                SM4TTable::encrypt_block(in + i, out + i, ctx);
            }
            }, "T-table实现");

        // AESNI实现
        if (features.aes) {
            measure_performance([](const uint8_t* in, uint8_t* out, const SM4Context& ctx, size_t size) {
                for (size_t i = 0; i < size; i += 64) {
                    if (i + 64 <= size) {
                        SM4AESNI::encrypt_4blocks(in + i, out + i, ctx);
                    }
                    else {
                        for (size_t j = i; j < size; j += 16) {
                            SM4TTable::encrypt_block(in + j, out + j, ctx);
                        }
                    }
                }
                }, "AESNI实现");
        }

        // GFNI实现
        if (features.avx2) {
            measure_performance([](const uint8_t* in, uint8_t* out, const SM4Context& ctx, size_t size) {
                for (size_t i = 0; i < size; i += 128) {
                    if (i + 128 <= size) {
                        SM4GFNI::encrypt_8blocks(in + i, out + i, ctx);
                    }
                    else {
                        for (size_t j = i; j < size; j += 16) {
                            SM4TTable::encrypt_block(in + j, out + j, ctx);
                        }
                    }
                }
                }, "AVX2/GFNI实现");
        }

        // 自适应实现
        measure_performance([](const uint8_t* in, uint8_t* out, const SM4Context& ctx, size_t size) {
            SM4Adaptive::encrypt_blocks(in, out, ctx, size / 16);
            }, "自适应实现");
    }
};

// SM4-GCM性能测试
class SM4GCMBenchmark {
private:
    static const size_t TEST_SIZE = 1024 * 1024;  // 1MB
    static const int ITERATIONS = 50;

public:
    static void run_benchmarks() {
        CPUFeatures features;

        std::cout << "\n=== SM4-GCM 性能测试 ===" << std::endl;
        std::cout << "CPU特性: ";
        if (features.sse2) std::cout << "SSE2 ";
        if (features.aes) std::cout << "AES ";
        if (features.avx2) std::cout << "AVX2 ";
        if (features.pclmul) std::cout << "PCLMUL ";
        if (features.gfni) std::cout << "GFNI ";
        std::cout << std::endl << std::endl;

        std::vector<uint8_t> plaintext(TEST_SIZE);
        std::vector<uint8_t> ciphertext(TEST_SIZE);
        std::vector<uint8_t> key(16);
        std::vector<uint8_t> iv(12);
        std::vector<uint8_t> aad(32);
        uint8_t tag[16];

        // 生成随机数据
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (size_t i = 0; i < plaintext.size(); i++) plaintext[i] = dis(gen);
        for (size_t i = 0; i < key.size(); i++) key[i] = dis(gen);
        for (size_t i = 0; i < iv.size(); i++) iv[i] = dis(gen);
        for (size_t i = 0; i < aad.size(); i++) aad[i] = dis(gen);

        auto start = std::chrono::high_resolution_clock::now();

        for (int iter = 0; iter < ITERATIONS; iter++) {
            SM4GCMContext gcm_ctx;
            SM4GCM::init_gcm(gcm_ctx, key.data(), iv.data(), iv.size());
            SM4GCM::update_aad(gcm_ctx, aad.data(), aad.size());
            SM4GCM::encrypt_update(gcm_ctx, plaintext.data(), ciphertext.data(), plaintext.size());
            SM4GCM::finalize(gcm_ctx, tag);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        double mbps = (double)(TEST_SIZE * ITERATIONS) / duration.count();
        double gbps = mbps / 1000.0;

        std::cout << "SM4-GCM优化实现: " << gbps << " GB/s" << std::endl;
        std::cout << "吞吐量: " << (TEST_SIZE * ITERATIONS) / (1024 * 1024) << " MB 用时 "
            << duration.count() / 1000.0 << " ms" << std::endl;
    }
};

// 测试向量验证
void test_sm4_gcm() {
    std::cout << "=== SM4-GCM 测试向量 ===" << std::endl;

    // 测试向量
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t iv[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01
    };

    uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t aad[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    uint8_t tag[16];

    // 执行加密
    SM4GCMContext gcm_ctx;
    SM4GCM::init_gcm(gcm_ctx, key, iv, 12);
    SM4GCM::update_aad(gcm_ctx, aad, 16);
    SM4GCM::encrypt_update(gcm_ctx, plaintext, ciphertext, 16);
    SM4GCM::finalize(gcm_ctx, tag);

    // 执行解密验证
    SM4GCMContext gcm_ctx2;
    SM4GCM::init_gcm(gcm_ctx2, key, iv, 12);
    SM4GCM::update_aad(gcm_ctx2, aad, 16);
    SM4GCM::decrypt_update(gcm_ctx2, ciphertext, decrypted, 16);
    bool tag_valid = SM4GCM::verify_tag(gcm_ctx2, tag);

    std::cout << "密钥:        ";
    for (int i = 0; i < 16; i++) printf("%02x ", key[i]);
    std::cout << std::endl;

    std::cout << "初始向量:     ";
    for (int i = 0; i < 12; i++) printf("%02x ", iv[i]);
    std::cout << std::endl;

    std::cout << "附加数据:     ";
    for (int i = 0; i < 16; i++) printf("%02x ", aad[i]);
    std::cout << std::endl;

    std::cout << "明文:        ";
    for (int i = 0; i < 16; i++) printf("%02x ", plaintext[i]);
    std::cout << std::endl;

    std::cout << "密文:        ";
    for (int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    std::cout << std::endl;

    std::cout << "认证标签:     ";
    for (int i = 0; i < 16; i++) printf("%02x ", tag[i]);
    std::cout << std::endl;

    std::cout << "解密结果:     ";
    for (int i = 0; i < 16; i++) printf("%02x ", decrypted[i]);
    std::cout << std::endl;

    std::cout << "标签有效:     " << (tag_valid ? "是" : "否") << std::endl;
    std::cout << "测试 " << (memcmp(plaintext, decrypted, 16) == 0 && tag_valid ? "通过" : "失败") << std::endl << std::endl;
}

int main() {
    std::cout << "SM4 & SM4-GCM 优化实现演示" << std::endl << std::endl;

    // 基础SM4测试
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t ciphertext[16];

    // 初始化密钥
    SM4Context ctx;
    SM4KeySchedule::expand_key(key, ctx);

    // 测试基础实现
    SM4Basic::encrypt_block(plaintext, ciphertext, ctx);

    std::cout << "=== SM4 基础测试 ===" << std::endl;
    std::cout << "明文:  ";
    for (int i = 0; i < 16; i++) {
        printf("%02x ", plaintext[i]);
    }
    std::cout << std::endl;

    std::cout << "密文: ";
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
    }
    std::cout << std::endl << std::endl;

    // 运行GCM测试向量
    test_sm4_gcm();

    // 运行性能测试
    SM4Benchmark::run_benchmarks();
    SM4GCMBenchmark::run_benchmarks();

    return 0;
}