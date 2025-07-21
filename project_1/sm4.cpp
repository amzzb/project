#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>
#include <random>
#include <immintrin.h>

#ifdef _MSC_VER
#include <intrin.h>
#define cpuid(info, x) __cpuidex(info, x, 0)
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
static inline void cpuid(int info[4], int level) {
    __cpuid_count(level, 0, info[0], info[1], info[2], info[3]);
}
#else
static inline void cpuid(int info[4], int level) {
    info[0] = info[1] = info[2] = info[3] = 0;
}
#endif

// SM4常量定义
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

// 工具函数
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// SM4上下文结构
struct SM4Context {
    uint32_t rk[32];  // 轮密钥
};

// CPU特性检测
struct CPUFeatures {
    bool sse2 = false;
    bool aes = false;
    bool avx2 = false;
    bool avx512f = false;
    bool gfni = false;
    bool vaes = false;

    CPUFeatures() {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
        int info[4];

        // 检测基础特性
        cpuid(info, 1);
        sse2 = (info[3] & (1 << 26)) != 0;
        aes = (info[2] & (1 << 25)) != 0;

        // 检测扩展特性
        cpuid(info, 7);
        avx2 = (info[1] & (1 << 5)) != 0;
        avx512f = (info[1] & (1 << 16)) != 0;
        gfni = (info[2] & (1 << 8)) != 0;
        vaes = (info[2] & (1 << 9)) != 0;
#else
        // 非x86平台，禁用所有特性
        sse2 = aes = avx2 = avx512f = gfni = vaes = false;
#endif
    }
};

// 基础实现类
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

// T-table优化实现
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

// AESNI优化实现
class SM4AESNI {
private:
    static __m128i sbox_sse(__m128i x) {
        // 使用查表方式实现S盒
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

public:
    static void encrypt_4blocks(const uint8_t* plaintext, uint8_t* ciphertext, const SM4Context& ctx) {
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

            // 计算t = x1 ^ x2 ^ x3 ^ rk
            __m128i t0 = _mm_xor_si128(_mm_xor_si128(x1, x2), _mm_xor_si128(x3, rk));

            // S盒变换
            t0 = sbox_sse(t0);

            // 线性变换
            t0 = linear_transform_sse(t0);

            // 更新状态
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
    }
};

// GFNI优化实现
class SM4GFNI {
private:
    static __m256i sbox_gfni(__m256i x) {
        // 检查编译时是否支持GFNI
#if defined(__GFNI__) && defined(__AVX2__)
// SM4 S盒的GFNI实现
        const __m256i matrix1 = _mm256_set1_epi64x(0x8040201008040201ULL);
        const __m256i matrix2 = _mm256_set1_epi64x(0x0102040810204080ULL);

        x = _mm256_gf2p8affine_epi64_epi8(x, matrix1, 0x63);
        x = _mm256_gf2p8inv_epi8(x);
        x = _mm256_gf2p8affine_epi64_epi8(x, matrix2, 0x8F);
        return x;
#else
// 回退到查表实现
        alignas(32) uint8_t tmp[32];
        _mm256_store_si256((__m256i*)tmp, x);
        for (int i = 0; i < 32; i++) {
            tmp[i] = SM4_SBOX[tmp[i]];
        }
        return _mm256_load_si256((__m256i*)tmp);
#endif
    }

    static __m256i linear_transform_avx2(__m256i x) {
#if defined(__AVX512VL__) && defined(__AVX512F__)
        __m256i result = x;
        result = _mm256_xor_si256(result, _mm256_rol_epi32(x, 2));
        result = _mm256_xor_si256(result, _mm256_rol_epi32(x, 10));
        result = _mm256_xor_si256(result, _mm256_rol_epi32(x, 18));
        result = _mm256_xor_si256(result, _mm256_rol_epi32(x, 24));
        return result;
#else
        // 使用标准移位指令
        __m256i t2 = _mm256_or_si256(_mm256_slli_epi32(x, 2), _mm256_srli_epi32(x, 30));
        __m256i t10 = _mm256_or_si256(_mm256_slli_epi32(x, 10), _mm256_srli_epi32(x, 22));
        __m256i t18 = _mm256_or_si256(_mm256_slli_epi32(x, 18), _mm256_srli_epi32(x, 14));
        __m256i t24 = _mm256_or_si256(_mm256_slli_epi32(x, 24), _mm256_srli_epi32(x, 8));

        return _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(x, t2), t10), t18), t24);
#endif
    }

public:
    static void encrypt_8blocks(const uint8_t* plaintext, uint8_t* ciphertext, const SM4Context& ctx) {
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

            // S盒变换
            t = sbox_gfni(t);

            // 线性变换
            t = linear_transform_avx2(t);

            // 更新状态
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

        // 加载密钥
        for (int i = 0; i < 4; i++) {
            k[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) |
                (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        }

        // 与FK异或
        for (int i = 0; i < 4; i++) {
            k[i] ^= FK[i];
        }

        // 生成轮密钥
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

// 性能测试类
class SM4Benchmark {
private:
    static constexpr size_t TEST_SIZE = 1024 * 1024;  // 1MB
    static constexpr int ITERATIONS = 100;

    template<typename Func>
    static double measure_performance(Func func, const std::string& name) {
        std::vector<uint8_t> plaintext(TEST_SIZE);
        std::vector<uint8_t> ciphertext(TEST_SIZE);
        std::vector<uint8_t> key(16);

        // 生成随机数据
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (auto& byte : plaintext) byte = dis(gen);
        for (auto& byte : key) byte = dis(gen);

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

        std::cout << "=== SM4 Performance Benchmark ===" << std::endl;
        std::cout << "CPU Features: ";
        if (features.sse2) std::cout << "SSE2 ";
        if (features.aes) std::cout << "AES ";
        if (features.avx2) std::cout << "AVX2 ";
        if (features.avx512f) std::cout << "AVX512F ";
        if (features.gfni) std::cout << "GFNI ";
        std::cout << std::endl << std::endl;

        // 基础实现
        measure_performance([](const uint8_t* in, uint8_t* out, const SM4Context& ctx, size_t size) {
            for (size_t i = 0; i < size; i += 16) {
                SM4Basic::encrypt_block(in + i, out + i, ctx);
            }
            }, "Basic Implementation");

        // T-table实现
        measure_performance([](const uint8_t* in, uint8_t* out, const SM4Context& ctx, size_t size) {
            for (size_t i = 0; i < size; i += 16) {
                SM4TTable::encrypt_block(in + i, out + i, ctx);
            }
            }, "T-table Implementation");

        // AESNI实现
        if (features.aes) {
            measure_performance([](const uint8_t* in, uint8_t* out, const SM4Context& ctx, size_t size) {
                for (size_t i = 0; i < size; i += 64) {
                    SM4AESNI::encrypt_4blocks(in + i, out + i, ctx);
                }
                }, "AESNI Implementation");
        }

        // GFNI实现
        if (features.avx2) {
            measure_performance([](const uint8_t* in, uint8_t* out, const SM4Context& ctx, size_t size) {
                for (size_t i = 0; i < size; i += 128) {
                    if (i + 128 <= size) {
                        SM4GFNI::encrypt_8blocks(in + i, out + i, ctx);
                    }
                }
                }, "AVX2/GFNI Implementation");
        }
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

int main() {
    std::cout << "SM4 Optimized Implementation Demo" << std::endl;

    // 测试数据
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

    std::cout << "Plaintext:  ";
    for (int i = 0; i < 16; i++) {
        printf("%02x ", plaintext[i]);
    }
    std::cout << std::endl;

    std::cout << "Ciphertext: ";
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
    }
    std::cout << std::endl << std::endl;

    // 运行性能测试
    SM4Benchmark::run_benchmarks();

    return 0;
}