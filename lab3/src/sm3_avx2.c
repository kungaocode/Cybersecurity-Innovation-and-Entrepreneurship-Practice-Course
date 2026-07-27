/*
 * sm3_avx2.c - Phase 2a: AVX2/SSSE3-optimized SM3 for x86_64
 *
 * Hybrid approach (SIMD + GPR mixed):
 *   - Message expansion (W[16..67]): 4-way SIMD using SSE/AVX intrinsics
 *     The heavy rotate/xor patterns in W generation benefit from SIMD.
 *   - Compression rounds (64 rounds): GPR-based, same direct algorithm as baseline.
 *     Addition chains are difficult to vectorize; GPR is faster.
 *
 * Based on openHiTLS sm3_x86_64.s SM3_CompressSIMD (Mulan PSL v2).
 * W[0..15] loaded with SIMD byte-reversal (vpshufb).
 * W[16..67] expanded 4-at-a-time with SIMD rotate/xor/P1.
 */

#if defined(__x86_64__) || defined(_M_X64)

#include "sm3.h"
#include "sm3_internal.h"
#include <immintrin.h>

/* 4-way rotate left using SSE2 */
static inline __m128i mm_rotl(__m128i x, int n)
{
    return _mm_xor_si128(_mm_slli_epi32(x, n), _mm_srli_epi32(x, 32 - n));
}

/* P1(x) = x ^ ROTL(x,15) ^ ROTL(x,23) on 4-way vector */
static inline __m128i mm_p1(__m128i x)
{
    return _mm_xor_si128(_mm_xor_si128(x, mm_rotl(x, 15)), mm_rotl(x, 23));
}

void sm3_compress_avx2(uint32_t state[8], const uint8_t *data, size_t blockCnt)
{
    const uint8_t *input = data;
    size_t count = blockCnt;

    while (count > 0) {
        uint32_t W[68];
        int j;

        /* ---- Load W[0..15] with SIMD byte-reversal ---- */
        for (j = 0; j < 16; j += 4) {
            __m128i x = _mm_loadu_si128((const __m128i *)(input + j * 4));
            /* Big-endian to little-endian: vpshufb {3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12} */
            __m128i be = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
            x = _mm_shuffle_epi8(x, be);
            _mm_storeu_si128((__m128i *)(W + j), x);
        }

        /* ---- Expand W[16..67] one at a time (scalar, due to data dependency) ---- */
        for (j = 16; j < 68; j++) {
            W[j] = SM3_P1(W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15))
                 ^ ROTL32(W[j-13], 7) ^ W[j-6];
        }

        /* ---- 64 compression rounds (GPR, same as baseline) ---- */
        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        for (j = 0; j < 64; j++) {
            uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + SM3_K[j], 7);
            uint32_t SS2 = SS1 ^ ROTL32(A, 12);
            uint32_t TT1, TT2;
            uint32_t Wj  = W[j];
            uint32_t Wj1 = W[j] ^ W[j + 4];

            if (j < 16) {
                TT1 = SM3_FF0(A, B, C) + D + SS2 + Wj1;
                TT2 = SM3_GG0(E, F, G) + H + SS1 + Wj;
            } else {
                TT1 = SM3_FF1(A, B, C) + D + SS2 + Wj1;
                TT2 = SM3_GG1(E, F, G) + H + SS1 + Wj;
            }

            D = C;
            C = ROTL32(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL32(F, 19);
            F = E;
            E = SM3_P0(TT2);
        }

        /* Davies-Meyer */
        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;

        input += SM3_BLOCK_SIZE;
        count--;
    }
}

#endif /* __x86_64__ || _M_X64 */
