/*
 * AES Experiment — AES-NI hardware-accelerated implementation
 *
 * Uses Intel AES New Instructions (AES-NI):
 *   aesenc, aesenclast  — one AES encryption round
 *   aesdec, aesdeclast  — one AES decryption round
 *   aeskeygenassist     — assist in key expansion
 *   aesimc              — inverse MixColumns for round-key conversion
 *
 * Available on Intel Westmere (2010) and later, and AMD Bulldozer and later.
 */

#include "aes_internal.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
#include <wmmintrin.h>  /* AES-NI */
#include <emmintrin.h>  /* SSE2 */
#include <cpuid.h>

int AES_HasAESNI(void)
{
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        return (ecx & bit_AES) ? 1 : 0;
    return 0;
}

/* ─── Round key buffer for AES-NI ─── */
#define AES_NI_MAX_ROUND_KEYS 15

typedef struct {
    __m128i rk[AES_NI_MAX_ROUND_KEYS];
    int     rounds;
} AES_NI_Key;

/* ─── Public API ─── */

/*
 * Convert scalar expanded key words to AES-NI __m128i format.
 * The scalar key stores big-endian uint32_t in LE memory.
 * AES-NI expects bytes in input order (byte 0 = first plaintext byte).
 * We bswap each word and place them in reverse order in the XMM.
 */
static inline __m128i rk_to_m128i(const uint32_t *rk)
{
    return _mm_set_epi32(
        (int)__builtin_bswap32(rk[3]),  /* e3: bits 127:96 */
        (int)__builtin_bswap32(rk[2]),  /* e2: bits 95:64  */
        (int)__builtin_bswap32(rk[1]),  /* e1: bits 63:32  */
        (int)__builtin_bswap32(rk[0])); /* e0: bits 31:0   */
}

int AES_NI_EncryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out)
{
    if (!AES_HasAESNI()) return -1;

    AES_NI_Key nk = {0};
    nk.rounds = ctx->rounds;
    for (int i = 0; i <= ctx->rounds; i++)
        nk.rk[i] = rk_to_m128i(ctx->rk + 4 * i);

    __m128i state = _mm_loadu_si128((const __m128i *)in);
    state = _mm_xor_si128(state, nk.rk[0]);

    int r;
    for (r = 1; r < nk.rounds; r++)
        state = _mm_aesenc_si128(state, nk.rk[r]);
    state = _mm_aesenclast_si128(state, nk.rk[r]);

    _mm_storeu_si128((__m128i *)out, state);
    return 0;
}

int AES_NI_DecryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out)
{
    if (!AES_HasAESNI()) return -1;

    /*
     * The scalar AES_SetDecryptKey already transforms middle round keys
     * with InvMixColumns for the equivalent inverse cipher.
     * We just load them in AES-NI byte order — no extra aesimc needed.
     */
    AES_NI_Key nk = {0};
    nk.rounds = ctx->rounds;
    for (int i = 0; i <= ctx->rounds; i++)
        nk.rk[i] = rk_to_m128i(ctx->rk + 4 * i);

    __m128i state = _mm_loadu_si128((const __m128i *)in);
    state = _mm_xor_si128(state, nk.rk[nk.rounds]);

    for (int r = nk.rounds - 1; r > 0; r--)
        state = _mm_aesdec_si128(state, nk.rk[r]);
    state = _mm_aesdeclast_si128(state, nk.rk[0]);

    _mm_storeu_si128((__m128i *)out, state);
    return 0;
}

#else  /* !x86 */

int AES_HasAESNI(void) { return 0; }

int AES_NI_EncryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out)
{
    (void)ctx; (void)in; (void)out;
    return -1;
}

int AES_NI_DecryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out)
{
    (void)ctx; (void)in; (void)out;
    return -1;
}

#endif /* x86 */
