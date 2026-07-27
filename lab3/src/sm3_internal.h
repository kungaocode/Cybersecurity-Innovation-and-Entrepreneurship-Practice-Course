/*
 * sm3_internal.h - Internal macros and constants for SM3
 *
 * Derived from GM/T 0004-2012 and openHiTLS.
 */

#ifndef SM3_INTERNAL_H
#define SM3_INTERNAL_H

#include <stdint.h>

/* Rotate left */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* Big-endian load/store */
static inline uint32_t load_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static inline void store_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

/* SM3 Initial Value (IV) from GM/T 0004-2012 section 4.1 */
#define SM3_IV_A  0x7380166FU
#define SM3_IV_B  0x4914B2B9U
#define SM3_IV_C  0x172442D7U
#define SM3_IV_D  0xDA8A0600U
#define SM3_IV_E  0xA96F30BCU
#define SM3_IV_F  0x163138AAU
#define SM3_IV_G  0xE38DEE4DU
#define SM3_IV_H  0xB0FB0E4EU

/* Permutation functions P0 and P1 */
#define SM3_P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x), 17))
#define SM3_P1(x) ((x) ^ ROTL32((x), 15) ^ ROTL32((x), 23))

/* Boolean functions FF and GG */
#define SM3_FF0(x, y, z) ((x) ^ (y) ^ (z))
#define SM3_FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define SM3_GG0(x, y, z) ((x) ^ (y) ^ (z))
#define SM3_GG1(x, y, z) (((x) & (y)) | (~(x) & (z)))

/*
 * Round constants Tj from GM/T 0004-2012 section 5.3.3:
 * For 0 <= j <= 15:  Tj = 0x79CC4519
 * For 16 <= j <= 63: Tj = 0x7A879D8A
 * Kj = Tj <<< j (pre-computed below)
 */
static const uint32_t SM3_K[64] = {
    0x79CC4519U, 0xF3988A32U, 0xE7311465U, 0xCE6228CBU,
    0x9CC45197U, 0x3988A32FU, 0x7311465EU, 0xE6228CBCU,
    0xCC451979U, 0x988A32F3U, 0x311465E7U, 0x6228CBCEU,
    0xC451979CU, 0x88A32F39U, 0x11465E73U, 0x228CBCE6U,
    0x9D8A7A87U, 0x3B14F50FU, 0x7629EA1EU, 0xEC53D43CU,
    0xD8A7A879U, 0xB14F50F3U, 0x629EA1E7U, 0xC53D43CEU,
    0x8A7A879DU, 0x14F50F3BU, 0x29EA1E76U, 0x53D43CECU,
    0xA7A879D8U, 0x4F50F3B1U, 0x9EA1E762U, 0x3D43CEC5U,
    0x7A879D8AU, 0xF50F3B14U, 0xEA1E7629U, 0xD43CEC53U,
    0xA879D8A7U, 0x50F3B14FU, 0xA1E7629EU, 0x43CEC53DU,
    0x879D8A7AU, 0x0F3B14F5U, 0x1E7629EAU, 0x3CEC53D4U,
    0x79D8A7A8U, 0xF3B14F50U, 0xE7629EA1U, 0xCEC53D43U,
    0x9D8A7A87U, 0x3B14F50FU, 0x7629EA1EU, 0xEC53D43CU,
    0xD8A7A879U, 0xB14F50F3U, 0x629EA1E7U, 0xC53D43CEU,
    0x8A7A879DU, 0x14F50F3BU, 0x29EA1E76U, 0x53D43CECU,
    0xA7A879D8U, 0x4F50F3B1U, 0x9EA1E762U, 0x3D43CEC5U
};

/*
 * Message expansion macro:
 * Wj = P1(W[j-16] ^ W[j-9] ^ (W[j-3] <<< 15)) ^ (W[j-13] <<< 7) ^ W[j-6]
 * P1(x) = x ^ (x <<< 15) ^ (x <<< 23)
 */
#define SM3_EXPAND(W0, W1, W2, W3, W4) \
    (SM3_P1((W0) ^ (W1) ^ ROTL32((W2), 15)) ^ ROTL32((W3), 7) ^ (W4))

/*
 * One SM3 compression round (used for all 64 rounds)
 *
 * A,B,C,D,E,F,G,H : state words (updated in place)
 * K  : round constant Kj
 * FF : FF0 for rounds 0..15, FF1 for rounds 16..63
 * GG : GG0 for rounds 0..15, GG1 for rounds 16..63
 * Wj : W[j] (message word j)
 * Wi : W'[j] = W[j] ^ W[j+4]
 */
#define SM3_ROUND(A, B, C, D, E, F, G, H, K, FF, GG, Wj, Wi)  \
    do {                                                         \
        uint32_t A12 = ROTL32((A), 12);                          \
        uint32_t SS1 = ROTL32(A12 + (E) + (K), 7);              \
        uint32_t SS2 = SS1 ^ A12;                                \
        uint32_t TT1 = FF((A), (B), (C)) + (D) + SS2 + (Wi);    \
        uint32_t TT2 = GG((E), (F), (G)) + (H) + SS1 + (Wj);    \
        (H) = TT1;  (D) = SM3_P0(TT2);                           \
        (B) = ROTL32((B), 9);  (F) = ROTL32((F), 19);            \
    } while (0)

#endif /* SM3_INTERNAL_H */
