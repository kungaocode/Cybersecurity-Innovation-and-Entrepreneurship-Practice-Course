/*
 * sm3_baseline.c - Phase 1: Pure C baseline SM3 compression function
 *
 * Direct implementation following GM/T 0004-2012 section 5.3.3.
 * All operations use plain C — no SIMD.
 *
 * Algorithm:
 *   1. Load W[0..15] from message block (big-endian)
 *   2. Expand W[16..67]: W[j] = P1(W[j-16]^W[j-9]^(W[j-3]<<<15)) ^ (W[j-13]<<<7) ^ W[j-6]
 *   3. 64 rounds with explicit state update per the standard
 */

#include "sm3.h"
#include "sm3_internal.h"

void sm3_compress(uint32_t state[8], const uint8_t *data, size_t blockCnt)
{
    const uint8_t *input = data;
    size_t count = blockCnt;

    while (count > 0) {
        uint32_t W[68];
        int j;

        /* ---- Step 1: Load W[0..15] (big-endian) ---- */
        for (j = 0; j < 16; j++) {
            W[j] = load_u32_be(input + j * 4);
        }

        /* ---- Step 2: Expand W[16..67] ---- */
        for (j = 16; j < 68; j++) {
            W[j] = SM3_P1(W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15))
                 ^ ROTL32(W[j-13], 7) ^ W[j-6];
        }

        /* ---- Step 3: 64 compression rounds ---- */
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
            uint32_t Wj = W[j];
            uint32_t Wj1 = W[j] ^ W[j + 4];  /* W'[j] = W[j] ^ W[j+4] */

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

        /* Davies-Meyer: XOR result with input state */
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
