/*
 * AES Experiment — SIMD Shuffle-based implementation (SSSE3/SSE2)
 *
 * Uses PSHUFB (SSSE3) for ShiftRows and SSE2 XOR for AddRoundKey.
 * SubBytes and MixColumns remain scalar (same as the S-box method).
 *
 * Speedup sources over the basic S-box method:
 *   - ShiftRows:   single PSHUFB instruction (vs. 4×32-bit bit manipulation)
 *   - AddRoundKey: 16-byte SSE XOR (vs. 4×32-bit XOR)
 *
 * Reference: "Accelerating AES with Vector Permute Instructions" (Hamburg 2009)
 */

#include "aes_internal.h"

#if defined(__SSSE3__) || defined(__SSE3__)
#include <tmmintrin.h>
#else
#include <smmintrin.h>
#endif
#include <emmintrin.h>

/* ─── CPU feature detection ─── */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
#include <cpuid.h>
int AES_HasSSSE3(void)
{
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        return (ecx & bit_SSSE3) ? 1 : 0;
    return 0;
}
#else
int AES_HasSSSE3(void) { return 0; }
#endif

/* ─── PSHUFB permutation masks for ShiftRows / InvShiftRows ─── */

#ifdef __GNUC__
#define ALIGNED16 __attribute__((aligned(16)))
#else
#define ALIGNED16
#endif

/*
 * ShiftRows (encrypt):
 *   Row 0 stays, Row 1 left-rotate 1, Row 2 left-rotate 2, Row 3 left-rotate 3.
 *   State is column-major: byte at position p = col*4+row.
 *   After shift: new[col*4+row] = old[((col+row)%4)*4 + row].
 *   PSHUFB: dst[i] = src[mask[i]].
 */
static const uint8_t SR_MASK[16] ALIGNED16 = {
    0,  5, 10, 15,   /* col0: row0←col0, row1←col1, row2←col2, row3←col3 */
    4,  9, 14,  3,   /* col1: row0←col1, row1←col2, row2←col3, row3←col0 */
    8, 13,  2,  7,   /* col2: row0←col2, row1←col3, row2←col0, row3←col1 */
    12, 1,  6, 11    /* col3: row0←col3, row1←col0, row2←col1, row3←col2 */
};

/*
 * InvShiftRows (decrypt):
 *   Row 0 stays, Row 1 right-rotate 1, Row 2 right-rotate 2, Row 3 right-rotate 3.
 *   new[col*4+row] = old[((col-row+4)%4)*4 + row].
 */
static const uint8_t ISR_MASK[16] ALIGNED16 = {
    0, 13, 10,  7,
    4,  1, 14, 11,
    8,  5,  2, 15,
    12, 9,  6,  3
};

/* ─── Scalar helpers — identical to aes_sbox.c ─── */

static void sub_bytes(uint32_t *s)
{
    for (int i = 0; i < 4; i++)
        s[i] = AES_SUB_WORD(s[i]);
}

static void inv_sub_bytes(uint32_t *s)
{
    for (int i = 0; i < 4; i++)
        s[i] = AES_INVSUB_WORD(s[i]);
}

static uint8_t gf_mul(uint8_t x, uint8_t y)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        if (y & 1) r ^= x;
        uint8_t hi = x & 0x80;
        x <<= 1;
        if (hi) x ^= 0x1b;
        y >>= 1;
    }
    return r;
}

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void mix_columns(uint32_t *s, int encrypt)
{
    uint8_t a[4][4], b[4][4];

    /* Extract: a[col][row] */
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            a[i][j] = (uint8_t)(s[i] >> (24 - 8 * j));

    for (int c = 0; c < 4; c++) {
        if (encrypt) {
            b[0][c] = xtime(a[c][0]) ^ (xtime(a[c][1]) ^ a[c][1]) ^ a[c][2] ^ a[c][3];
            b[1][c] = a[c][0] ^ xtime(a[c][1]) ^ (xtime(a[c][2]) ^ a[c][2]) ^ a[c][3];
            b[2][c] = a[c][0] ^ a[c][1] ^ xtime(a[c][2]) ^ (xtime(a[c][3]) ^ a[c][3]);
            b[3][c] = (xtime(a[c][0]) ^ a[c][0]) ^ a[c][1] ^ a[c][2] ^ xtime(a[c][3]);
        } else {
            b[0][c] = gf_mul(a[c][0], 0x0e) ^ gf_mul(a[c][1], 0x0b) ^ gf_mul(a[c][2], 0x0d) ^ gf_mul(a[c][3], 0x09);
            b[1][c] = gf_mul(a[c][0], 0x09) ^ gf_mul(a[c][1], 0x0e) ^ gf_mul(a[c][2], 0x0b) ^ gf_mul(a[c][3], 0x0d);
            b[2][c] = gf_mul(a[c][0], 0x0d) ^ gf_mul(a[c][1], 0x09) ^ gf_mul(a[c][2], 0x0e) ^ gf_mul(a[c][3], 0x0b);
            b[3][c] = gf_mul(a[c][0], 0x0b) ^ gf_mul(a[c][1], 0x0d) ^ gf_mul(a[c][2], 0x09) ^ gf_mul(a[c][3], 0x0e);
        }
    }

    for (int i = 0; i < 4; i++) {
        s[i] = ((uint32_t)b[0][i] << 24) | ((uint32_t)b[1][i] << 16) |
               ((uint32_t)b[2][i] <<  8) | ((uint32_t)b[3][i]);
    }
}

/* ─── PSHUFB-based ShiftRows ─── */

static void shuffle_shift_rows(uint8_t *state)
{
    __m128i s = _mm_loadu_si128((const __m128i *)state);
    s = _mm_shuffle_epi8(s, _mm_load_si128((const __m128i *)SR_MASK));
    _mm_storeu_si128((__m128i *)state, s);
}

static void shuffle_inv_shift_rows(uint8_t *state)
{
    __m128i s = _mm_loadu_si128((const __m128i *)state);
    s = _mm_shuffle_epi8(s, _mm_load_si128((const __m128i *)ISR_MASK));
    _mm_storeu_si128((__m128i *)state, s);
}

/* ─── SSE-based AddRoundKey ─── */

static void shuffle_add_round_key(uint32_t *s, const uint32_t *rk, int round)
{
    __m128i ss = _mm_loadu_si128((const __m128i *)s);
    __m128i rr = _mm_loadu_si128((const __m128i *)(rk + 4 * round));
    ss = _mm_xor_si128(ss, rr);
    _mm_storeu_si128((__m128i *)s, ss);
}

/* ─── Public API ─── */

int AES_SHUFFLE_EncryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out)
{
    if (!AES_HasSSSE3()) return -1;

    uint32_t s[4];
    /* Load state as 4×32-bit words in column-major order */
    uint8_t state_bytes[16];
    memcpy(state_bytes, in, 16);

    for (int i = 0; i < 4; i++)
        s[i] = LOAD_U32_BE(in + 4 * i);

    /* Initial AddRoundKey via SSE */
    shuffle_add_round_key(s, ctx->rk, 0);

    for (int r = 1; r < ctx->rounds; r++) {
        /* SubBytes — scalar */
        sub_bytes(s);

        /* Store to byte array for PSHUFB ShiftRows, then load back */
        for (int i = 0; i < 4; i++)
            STORE_U32_BE(state_bytes + 4 * i, s[i]);
        shuffle_shift_rows(state_bytes);
        for (int i = 0; i < 4; i++)
            s[i] = LOAD_U32_BE(state_bytes + 4 * i);

        /* MixColumns — scalar (same as S-box method) */
        mix_columns(s, 1);

        /* AddRoundKey via SSE */
        shuffle_add_round_key(s, ctx->rk, r);
    }

    /* Last round */
    sub_bytes(s);
    for (int i = 0; i < 4; i++)
        STORE_U32_BE(state_bytes + 4 * i, s[i]);
    shuffle_shift_rows(state_bytes);
    for (int i = 0; i < 4; i++)
        s[i] = LOAD_U32_BE(state_bytes + 4 * i);
    shuffle_add_round_key(s, ctx->rk, ctx->rounds);

    for (int i = 0; i < 4; i++)
        STORE_U32_BE(out + 4 * i, s[i]);

    aes_cleanse(state_bytes, sizeof(state_bytes));
    return 0;
}

int AES_SHUFFLE_DecryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out)
{
    if (!AES_HasSSSE3()) return -1;

    uint32_t s[4];
    uint8_t state_bytes[16];

    for (int i = 0; i < 4; i++)
        s[i] = LOAD_U32_BE(in + 4 * i);

    /* Equivalent inverse cipher per FIPS 197 Section 5.3.5 */
    shuffle_add_round_key(s, ctx->rk, ctx->rounds);

    for (int r = ctx->rounds - 1; r > 0; r--) {
        inv_sub_bytes(s);

        for (int i = 0; i < 4; i++)
            STORE_U32_BE(state_bytes + 4 * i, s[i]);
        shuffle_inv_shift_rows(state_bytes);
        for (int i = 0; i < 4; i++)
            s[i] = LOAD_U32_BE(state_bytes + 4 * i);

        mix_columns(s, 0);
        shuffle_add_round_key(s, ctx->rk, r);
    }

    inv_sub_bytes(s);
    for (int i = 0; i < 4; i++)
        STORE_U32_BE(state_bytes + 4 * i, s[i]);
    shuffle_inv_shift_rows(state_bytes);
    for (int i = 0; i < 4; i++)
        s[i] = LOAD_U32_BE(state_bytes + 4 * i);
    shuffle_add_round_key(s, ctx->rk, 0);

    for (int i = 0; i < 4; i++)
        STORE_U32_BE(out + 4 * i, s[i]);

    aes_cleanse(state_bytes, sizeof(state_bytes));
    return 0;
}
