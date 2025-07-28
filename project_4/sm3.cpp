#include <cstdint>
#include <cstring>
#include <vector>
#include <immintrin.h>  // X86 SIMD
#include <arm_neon.h>   
class SM3 {
private:
    // SM3初始值
    static constexpr uint32_t IV[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    // 常量Tj
    static constexpr uint32_t T1 = 0x79cc4519;
    static constexpr uint32_t T2 = 0x7a879d8a;

public:
    // 基础版本
    void sm3_standard(const uint8_t* message, size_t len, uint8_t* digest);

    // 优化版本
    void sm3_optimized(const uint8_t* message, size_t len, uint8_t* digest);

#ifdef __x86_64__
    // X86-64 SIMD优化版本
    void sm3_avx2(const uint8_t* message, size_t len, uint8_t* digest);
    void sm3_avx512(const uint8_t* message, size_t len, uint8_t* digest);
#endif

#ifdef __aarch64__
    // ARM64 NEON优化版本
    void sm3_neon(const uint8_t* message, size_t len, uint8_t* digest);
#endif

private:
    // 辅助函数
    static inline uint32_t ROTL32(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline uint32_t P0(uint32_t x) {
        return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
    }

    static inline uint32_t P1(uint32_t x) {
        return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
    }

    static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (~x & z));
    }

    // 字节序转换
    static inline uint32_t bswap32(uint32_t x) {
        return __builtin_bswap32(x);
    }

    // 消息扩展 - 标准版本
    void message_expansion_standard(const uint32_t* B, uint32_t* W, uint32_t* W_prime);

    // 消息扩展 - 优化版本
    void message_expansion_optimized(const uint32_t* B, uint32_t* W, uint32_t* W_prime);

    // 压缩函数 - 标准版本
    void compression_standard(uint32_t* V, const uint32_t* W, const uint32_t* W_prime);

    // 压缩函数 - 优化版本
    void compression_optimized(uint32_t* V, const uint32_t* W, const uint32_t* W_prime);

#ifdef __x86_64__
    // X86-64特定优化
    void message_expansion_avx2(const uint32_t* B, uint32_t* W, uint32_t* W_prime);
    void compression_x86_optimized(uint32_t* V, const uint32_t* W, const uint32_t* W_prime);
#endif

#ifdef __aarch64__
    // ARM64特定优化
    void message_expansion_neon(const uint32_t* B, uint32_t* W, uint32_t* W_prime);
    void compression_arm_optimized(uint32_t* V, const uint32_t* W, const uint32_t* W_prime);
#endif

    // 填充函数
    std::vector<uint8_t> padding(const uint8_t* message, size_t len);
};

//标准实现
void SM3::sm3_standard(const uint8_t* message, size_t len, uint8_t* digest) {
    std::vector<uint8_t> padded_msg = padding(message, len);

    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    // 处理每个512位分组
    for (size_t i = 0; i < padded_msg.size(); i += 64) {
        uint32_t B[16];
        for (int j = 0; j < 16; j++) {
            B[j] = bswap32(*(uint32_t*)&padded_msg[i + j * 4]);
        }

        uint32_t W[68], W_prime[64];
        message_expansion_standard(B, W, W_prime);
        compression_standard(V, W, W_prime);
    }

    // 输出最终结果
    for (int i = 0; i < 8; i++) {
        *(uint32_t*)(digest + i * 4) = bswap32(V[i]);
    }
}

void SM3::message_expansion_standard(const uint32_t* B, uint32_t* W, uint32_t* W_prime) {
    // 复制前16个字
    for (int j = 0; j < 16; j++) {
        W[j] = B[j];
    }

    // 扩展剩余52个字
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
    }

    // 生成W'
    for (int j = 0; j < 64; j++) {
        W_prime[j] = W[j] ^ W[j + 4];
    }
}

void SM3::compression_standard(uint32_t* V, const uint32_t* W, const uint32_t* W_prime) {
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t Tj = (j < 16) ? T1 : T2;
        uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(Tj, j % 32), 7);
        uint32_t SS2 = SS1 ^ ROTL32(A, 12);
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W_prime[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

//优化实现
void SM3::sm3_optimized(const uint8_t* message, size_t len, uint8_t* digest) {
    std::vector<uint8_t> padded_msg = padding(message, len);

    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    for (size_t i = 0; i < padded_msg.size(); i += 64) {
        uint32_t B[16];
        for (int j = 0; j < 16; j++) {
            B[j] = bswap32(*(uint32_t*)&padded_msg[i + j * 4]);
        }

        uint32_t W[68], W_prime[64];
        message_expansion_optimized(B, W, W_prime);
        compression_optimized(V, W, W_prime);
    }

    for (int i = 0; i < 8; i++) {
        *(uint32_t*)(digest + i * 4) = bswap32(V[i]);
    }
}

void SM3::message_expansion_optimized(const uint32_t* B, uint32_t* W, uint32_t* W_prime) {
    // 使用寄存器优化的实现
    register uint32_t w0, w1, w2, w3, w4, w5, w6, w7;
    register uint32_t w8, w9, w10, w11, w12, w13, w14, w15;

    // 加载前16个字到寄存器
    w0 = B[0]; w1 = B[1]; w2 = B[2]; w3 = B[3];
    w4 = B[4]; w5 = B[5]; w6 = B[6]; w7 = B[7];
    w8 = B[8]; w9 = B[9]; w10 = B[10]; w11 = B[11];
    w12 = B[12]; w13 = B[13]; w14 = B[14]; w15 = B[15];

    W[0] = w0; W[1] = w1; W[2] = w2; W[3] = w3;
    W[4] = w4; W[5] = w5; W[6] = w6; W[7] = w7;
    W[8] = w8; W[9] = w9; W[10] = w10; W[11] = w11;
    W[12] = w12; W[13] = w13; W[14] = w14; W[15] = w15;

    // 展开计算减少循环开销
#define EXPAND_W(j) \
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15)) ^ ROTL32(W[j-13], 7) ^ W[j-6]

    for (int j = 16; j < 68; j++) {
        EXPAND_W(j);
    }

    // 优化W'计算
    for (int j = 0; j < 64; j += 4) {
        W_prime[j] = W[j] ^ W[j + 4];
        W_prime[j + 1] = W[j + 1] ^ W[j + 5];
        W_prime[j + 2] = W[j + 2] ^ W[j + 6];
        W_prime[j + 3] = W[j + 3] ^ W[j + 7];
    }
}

void SM3::compression_optimized(uint32_t* V, const uint32_t* W, const uint32_t* W_prime) {
    register uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    register uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    // 消除字置换的4轮组合宏
#define ROUND_FUNC(a, b, c, d, e, f, g, h, j) do { \
        uint32_t Tj = (j < 16) ? T1 : T2; \
        uint32_t SS1 = ROTL32(ROTL32(a, 12) + e + ROTL32(Tj, j % 32), 7); \
        uint32_t SS2 = SS1 ^ ROTL32(a, 12); \
        uint32_t TT1 = FF(a, b, c, j) + d + SS2 + W_prime[j]; \
        uint32_t TT2 = GG(e, f, g, j) + h + SS1 + W[j]; \
        d = c; \
        c = ROTL32(b, 9); \
        b = a; \
        a = TT1; \
        h = g; \
        g = ROTL32(f, 19); \
        f = e; \
        e = P0(TT2); \
    } while(0)

    // 4轮组合，消除置换操作
    for (int j = 0; j < 64; j += 4) {
        ROUND_FUNC(A, B, C, D, E, F, G, H, j);
        ROUND_FUNC(D, A, B, C, H, E, F, G, j + 1);
        ROUND_FUNC(C, D, A, B, G, H, E, F, j + 2);
        ROUND_FUNC(B, C, D, A, F, G, H, E, j + 3);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

#ifdef __x86_64__
//X86-64 AVX2优化
void SM3::sm3_avx2(const uint8_t* message, size_t len, uint8_t* digest) {
    std::vector<uint8_t> padded_msg = padding(message, len);

    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    for (size_t i = 0; i < padded_msg.size(); i += 64) {
        uint32_t B[16];
        for (int j = 0; j < 16; j++) {
            B[j] = bswap32(*(uint32_t*)&padded_msg[i + j * 4]);
        }

        uint32_t W[68], W_prime[64];
        message_expansion_avx2(B, W, W_prime);
        compression_x86_optimized(V, W, W_prime);
    }

    for (int i = 0; i < 8; i++) {
        *(uint32_t*)(digest + i * 4) = bswap32(V[i]);
    }
}

void SM3::message_expansion_avx2(const uint32_t* B, uint32_t* W, uint32_t* W_prime) {
    // 加载前16个字到SIMD寄存器
    __m128i xmm0 = _mm_loadu_si128((__m128i*) & B[0]);   // w0,w1,w2,w3
    __m128i xmm1 = _mm_loadu_si128((__m128i*) & B[4]);   // w4,w5,w6,w7
    __m128i xmm2 = _mm_loadu_si128((__m128i*) & B[8]);   // w8,w9,w10,w11
    __m128i xmm3 = _mm_loadu_si128((__m128i*) & B[12]);  // w12,w13,w14,w15

    _mm_storeu_si128((__m128i*) & W[0], xmm0);
    _mm_storeu_si128((__m128i*) & W[4], xmm1);
    _mm_storeu_si128((__m128i*) & W[8], xmm2);
    _mm_storeu_si128((__m128i*) & W[12], xmm3);

    // SIMD消息扩展
    for (int j = 16; j < 68; j += 4) {
        // 使用改进的分组方式减少拼接操作
        __m128i w_j_16 = _mm_loadu_si128((__m128i*) & W[j - 16]);
        __m128i w_j_9 = _mm_loadu_si128((__m128i*) & W[j - 9]);
        __m128i w_j_3 = _mm_loadu_si128((__m128i*) & W[j - 3]);
        __m128i w_j_13 = _mm_loadu_si128((__m128i*) & W[j - 13]);
        __m128i w_j_6 = _mm_loadu_si128((__m128i*) & W[j - 6]);

        // 实现P1函数的SIMD版本
        __m128i temp1 = _mm_xor_si128(w_j_16, w_j_9);

        // 循环左移15位 (SIMD没有直接的循环移位，需要组合)
        __m128i rot15_l = _mm_slli_epi32(w_j_3, 15);
        __m128i rot15_r = _mm_srli_epi32(w_j_3, 17);
        __m128i rot15 = _mm_or_si128(rot15_l, rot15_r);

        temp1 = _mm_xor_si128(temp1, rot15);

        // P1函数实现
        __m128i p1_15_l = _mm_slli_epi32(temp1, 15);
        __m128i p1_15_r = _mm_srli_epi32(temp1, 17);
        __m128i p1_15 = _mm_or_si128(p1_15_l, p1_15_r);

        __m128i p1_23_l = _mm_slli_epi32(temp1, 23);
        __m128i p1_23_r = _mm_srli_epi32(temp1, 9);
        __m128i p1_23 = _mm_or_si128(p1_23_l, p1_23_r);

        __m128i p1_result = _mm_xor_si128(temp1, p1_15);
        p1_result = _mm_xor_si128(p1_result, p1_23);

        // 循环左移7位
        __m128i rot7_l = _mm_slli_epi32(w_j_13, 7);
        __m128i rot7_r = _mm_srli_epi32(w_j_13, 25);
        __m128i rot7 = _mm_or_si128(rot7_l, rot7_r);

        __m128i result = _mm_xor_si128(p1_result, rot7);
        result = _mm_xor_si128(result, w_j_6);

        _mm_storeu_si128((__m128i*) & W[j], result);
    }

    // 生成W'
    for (int j = 0; j < 64; j += 4) {
        __m128i wj = _mm_loadu_si128((__m128i*) & W[j]);
        __m128i wj4 = _mm_loadu_si128((__m128i*) & W[j + 4]);
        __m128i wprime = _mm_xor_si128(wj, wj4);
        _mm_storeu_si128((__m128i*) & W_prime[j], wprime);
    }
}

void SM3::compression_x86_optimized(uint32_t* V, const uint32_t* W, const uint32_t* W_prime) {
    // 使用内联汇编进行优化
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    // 预计算所有Tj<<<j值
    uint32_t T_rotated[64];
    for (int j = 0; j < 64; j++) {
        uint32_t Tj = (j < 16) ? T1 : T2;
        T_rotated[j] = ROTL32(Tj, j % 32);
    }

    // 使用内联汇编优化关键路径
    for (int j = 0; j < 64; j++) {
        uint32_t SS1, SS2, TT1, TT2;

        asm volatile (
            "movl %[A], %%eax\n\t"
            "roll $12, %%eax\n\t"
            "addl %[E], %%eax\n\t"
            "addl %[Tj], %%eax\n\t"
            "roll $7, %%eax\n\t"
            "movl %%eax, %[SS1]\n\t"

            "movl %[A], %%ebx\n\t"
            "roll $12, %%ebx\n\t"
            "xorl %%eax, %%ebx\n\t"
            "movl %%ebx, %[SS2]\n\t"
            : [SS1] "=m" (SS1), [SS2] "=m" (SS2)
            : [A] "m" (A), [E] "m" (E), [Tj] "m" (T_rotated[j])
            : "eax", "ebx"
            );

        TT1 = FF(A, B, C, j) + D + SS2 + W_prime[j];
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

#ifdef __AVX512F__
void SM3::sm3_avx512(const uint8_t* message, size_t len, uint8_t* digest) {
    // AVX512实现，使用VPTERNLOGD和VPROLD指令
    // 这里省略具体实现，原理类似AVX2但使用更强的指令
}
#endif

#endif // __x86_64__

#ifdef __aarch64__
//ARM64 NEON优化
void SM3::sm3_neon(const uint8_t* message, size_t len, uint8_t* digest) {
    std::vector<uint8_t> padded_msg = padding(message, len);

    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    for (size_t i = 0; i < padded_msg.size(); i += 64) {
        uint32_t B[16];
        for (int j = 0; j < 16; j++) {
            B[j] = __builtin_bswap32(*(uint32_t*)&padded_msg[i + j * 4]);
        }

        uint32_t W[68], W_prime[64];
        message_expansion_neon(B, W, W_prime);
        compression_arm_optimized(V, W, W_prime);
    }

    for (int i = 0; i < 8; i++) {
        *(uint32_t*)(digest + i * 4) = __builtin_bswap32(V[i]);
    }
}

void SM3::message_expansion_neon(const uint32_t* B, uint32_t* W, uint32_t* W_prime) {
    // 加载前16个字到NEON寄存器
    uint32x4_t v0 = vld1q_u32(&B[0]);   // w0,w1,w2,w3
    uint32x4_t v1 = vld1q_u32(&B[4]);   // w4,w5,w6,w7
    uint32x4_t v2 = vld1q_u32(&B[8]);   // w8,w9,w10,w11
    uint32x4_t v3 = vld1q_u32(&B[12]);  // w12,w13,w14,w15

    vst1q_u32(&W[0], v0);
    vst1q_u32(&W[4], v1);
    vst1q_u32(&W[8], v2);
    vst1q_u32(&W[12], v3);

    // NEON消息扩展
    for (int j = 16; j < 68; j += 4) {
        uint32x4_t w_j_16 = vld1q_u32(&W[j - 16]);
        uint32x4_t w_j_9 = vld1q_u32(&W[j - 9]);
        uint32x4_t w_j_3 = vld1q_u32(&W[j - 3]);
        uint32x4_t w_j_13 = vld1q_u32(&W[j - 13]);
        uint32x4_t w_j_6 = vld1q_u32(&W[j - 6]);

        // ARM64循环左移实现
        uint32x4_t temp1 = veorq_u32(w_j_16, w_j_9);

        // 循环左移15位
        uint32x4_t rot15_l = vshlq_n_u32(w_j_3, 15);
        uint32x4_t rot15_r = vshrq_n_u32(w_j_3, 17);
        uint32x4_t rot15 = vorrq_u32(rot15_l, rot15_r);

        temp1 = veorq_u32(temp1, rot15);

        // P1函数的NEON实现
        uint32x4_t p1_15_l = vshlq_n_u32(temp1, 15);
        uint32x4_t p1_15_r = vshrq_n_u32(temp1, 17);
        uint32x4_t p1_15 = vorrq_u32(p1_15_l, p1_15_r);

        uint32x4_t p1_23_l = vshlq_n_u32(temp1, 23);
        uint32x4_t p1_23_r = vshrq_n_u32(temp1, 9);
        uint32x4_t p1_23 = vorrq_u32(p1_23_l, p1_23_r);

        uint32x4_t p1_result = veorq_u32(temp1, p1_15);
        p1_result = veorq_u32(p1_result, p1_23);

        // 循环左移7位
        uint32x4_t rot7_l = vshlq_n_u32(w_j_13, 7);
        uint32x4_t rot7_r = vshrq_n_u32(w_j_13, 25);
        uint32x4_t rot7 = vorrq_u32(rot7_l, rot7_r);

        uint32x4_t result = veorq_u32(p1_result, rot7);
        result = veorq_u32(result, w_j_6);

        vst1q_u32(&W[j], result);
    }

    // 生成W'
    for (int j = 0; j < 64; j += 4) {
        uint32x4_t wj = vld1q_u32(&W[j]);
        uint32x4_t wj4 = vld1q_u32(&W[j + 4]);
        uint32x4_t wprime = veorq_u32(wj, wj4);
        vst1q_u32(&W_prime[j], wprime);
    }
}

void SM3::compression_arm_optimized(uint32_t* V, const uint32_t* W, const uint32_t* W_prime) {
    // ARM64全寄存器优化实现
    register uint32_t A asm("w0") = V[0];
    register uint32_t B asm("w1") = V[1];
    register uint32_t C asm("w2") = V[2];
    register uint32_t D asm("w3") = V[3];
    register uint32_t E asm("w4") = V[4];
    register uint32_t F asm("w5") = V[5];
    register uint32_t G asm("w6") = V[6];
    register uint32_t H asm("w7") = V[7];

    // 利用ARM64桶形移位寄存器和内联汇编
    for (int j = 0; j < 64; j++) {
        uint32_t Tj = (j < 16) ? T1 : T2;
        uint32_t SS1, SS2, TT1, TT2;

        // 使用ARM64内联汇编优化
        asm volatile (
            "ror w8, %w[A], #20\n\t"     // A<<<12
            "add w8, w8, %w[E]\n\t"      // + E
            "add w8, w8, %w[Tj], ror %[rot]\n\t"  // + Tj<<<j
            "ror %w[SS1], w8, #25\n\t"   // <<<7
            "eor %w[SS2], %w[SS1], %w[A], ror #20\n\t"  // SS1 ^ A<<<12
            : [SS1] "=&r" (SS1), [SS2] "=&r" (SS2)
            : [A] "r" (A), [E] "r" (E), [Tj] "r" (Tj), [rot] "i" (j % 32)
            : "w8"
            );

        TT1 = FF(A, B, C, j) + D + SS2 + W_prime[j];
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        D = C;
        asm volatile ("ror %w[C], %w[B], #23" : [C] "=r" (C) : [B] "r" (B));  // B<<<9
        B = A;
        A = TT1;
        H = G;
        asm volatile ("ror %w[G], %w[F], #13" : [G] "=r" (G) : [F] "r" (F));  // F<<<19
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

#endif // __aarch64__

//填充函数
std::vector<uint8_t> SM3::padding(const uint8_t* message, size_t len) {
    size_t bit_len = len * 8;
    size_t padding_len = (448 - (bit_len + 1) % 512 + 512) % 512;
    size_t total_len = len + 1 + padding_len / 8 + 8;

    std::vector<uint8_t> padded(total_len);

    // 复制原始消息
    memcpy(padded.data(), message, len);

    // 添加'1'位
    padded[len] = 0x80;

    // 添加0填充
    for (size_t i = len + 1; i < total_len - 8; i++) {
        padded[i] = 0;
    }

    // 添加长度（大端序）
    for (int i = 0; i < 8; i++) {
        padded[total_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xff;
    }

    return padded;
}

//使用示例
#include <iostream>
#include <iomanip>

void print_hash(const uint8_t* hash) {
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << std::endl;
}

int main() {
    SM3 sm3;
    const char* message = "abc";
    uint8_t digest[32];

    std::cout << "Testing SM3 implementations:\n";

    // 标准版本
    sm3.sm3_standard((const uint8_t*)message, strlen(message), digest);
    std::cout << "Standard: ";
    print_hash(digest);

    // 优化版本
    sm3.sm3_optimized((const uint8_t*)message, strlen(message), digest);
    std::cout << "Optimized: ";
    print_hash(digest);

#ifdef __x86_64__
    // AVX2版本
    sm3.sm3_avx2((const uint8_t*)message, strlen(message), digest);
    std::cout << "AVX2: ";
    print_hash(digest);
#endif

#ifdef __aarch64__
    // NEON版本
    sm3.sm3_neon((const uint8_t*)message, strlen(message), digest);
    std::cout << "NEON: ";
    print_hash(digest);
#endif

    return 0;
}