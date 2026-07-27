/*
 * sm3_public.c - SM3 public API: Init, Update, Final, HMAC
 *
 * Adapted from openHiTLS sm3_public.c (Mulan PSL v2).
 * Uses standard C library functions only.
 */

#include "sm3.h"
#include "sm3_internal.h"

#include <string.h>

/* ---- Compression function selection ---- */

/*
 * SM3_HAS_SIMD is defined via Makefile for AVX2/NEON builds.
 * When not defined, always falls back to baseline C.
 *
 * On x86_64 with SM3_HAS_SIMD: use AVX2 SIMD message expansion.
 * On aarch64 with SM3_HAS_SIMD: use NEON SIMD message expansion.
 * On aarch64 without SM3_HAS_SIMD: use baseline C (NEON function not linked).
 * Otherwise: use baseline C.
 */

#if defined(SM3_HAS_SIMD) && (defined(__x86_64__) || defined(_M_X64))
#define SM3_USE_AVX2 1
#elif defined(SM3_HAS_SIMD) && (defined(__aarch64__) || defined(__ARM_NEON))
#define SM3_USE_NEON 1
#endif

static void sm3_compress_dispatch(uint32_t state[8], const uint8_t *data, size_t blockCnt)
{
#if defined(SM3_USE_AVX2)
    sm3_compress_avx2(state, data, blockCnt);
#elif defined(SM3_USE_NEON)
    sm3_compress_neon(state, data, blockCnt);
#else
    sm3_compress(state, data, blockCnt);
#endif
}

/* ---- Public API ---- */

void sm3_init(sm3_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = SM3_IV_A;
    ctx->state[1] = SM3_IV_B;
    ctx->state[2] = SM3_IV_C;
    ctx->state[3] = SM3_IV_D;
    ctx->state[4] = SM3_IV_E;
    ctx->state[5] = SM3_IV_F;
    ctx->state[6] = SM3_IV_G;
    ctx->state[7] = SM3_IV_H;
}

void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (len == 0) return;

    /* Update bit count */
    uint64_t bits = (uint64_t)len * 8;
    uint32_t lo = ctx->lNum + (uint32_t)bits;
    ctx->lNum = lo;
    if (lo < (uint32_t)bits) ctx->hNum++;
    ctx->hNum += (uint32_t)(bits >> 32);

    size_t left = SM3_BLOCK_SIZE - ctx->num;

    if (ctx->num != 0) {
        if (len < left) {
            memcpy(ctx->block + ctx->num, data, len);
            ctx->num += len;
            return;
        }
        memcpy(ctx->block + ctx->num, data, left);
        sm3_compress_dispatch(ctx->state, ctx->block, 1);
        data += left;
        len -= left;
        ctx->num = 0;
    }

    size_t blockCnt = len / SM3_BLOCK_SIZE;
    if (blockCnt > 0) {
        sm3_compress_dispatch(ctx->state, data, blockCnt);
        size_t consumed = blockCnt * SM3_BLOCK_SIZE;
        data += consumed;
        len -= consumed;
    }

    if (len > 0) {
        memcpy(ctx->block, data, len);
        ctx->num = len;
    }
}

void sm3_final(sm3_ctx_t *ctx, uint8_t digest[SM3_DIGEST_SIZE])
{
    /* Padding: append 0x80, then zeros, then 64-bit bit-length (big-endian) */
    ctx->block[ctx->num++] = 0x80;

    size_t left = SM3_BLOCK_SIZE - ctx->num;

    if (left < 8) {
        /* Not enough room for length field — pad and compress */
        memset(ctx->block + ctx->num, 0, left);
        sm3_compress_dispatch(ctx->state, ctx->block, 1);
        ctx->num = 0;
        left = SM3_BLOCK_SIZE;
    }

    /* Pad with zeros, leave 8 bytes for bit-length */
    memset(ctx->block + ctx->num, 0, left - 8);

    /* Store 64-bit bit-length at end of block (big-endian) */
    store_u32_be(ctx->block + SM3_BLOCK_SIZE - 8, ctx->hNum);
    store_u32_be(ctx->block + SM3_BLOCK_SIZE - 4, ctx->lNum);

    sm3_compress_dispatch(ctx->state, ctx->block, 1);

    /* Output digest (big-endian) */
    for (int i = 0; i < 8; i++) {
        store_u32_be(digest + i * 4, ctx->state[i]);
    }

    /* Clear context */
    memset(ctx, 0, sizeof(*ctx));
}

void sm3_hash(const uint8_t *msg, size_t len, uint8_t digest[SM3_DIGEST_SIZE])
{
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, msg, len);
    sm3_final(&ctx, digest);
}

/*
 * HMAC-SM3 (RFC 2104 / GM/T 0004-2012):
 *
 *   HMAC(K, m) = H( (K' ^ opad) || H( (K' ^ ipad) || m) )
 *
 * where K' = K if |K| <= block_size, else H(K).
 * ipad = 0x36 repeated, opad = 0x5C repeated.
 */
void sm3_hmac(const uint8_t *key, size_t key_len,
              const uint8_t *msg, size_t msg_len,
              uint8_t mac[SM3_HMAC_SIZE])
{
    uint8_t key_block[SM3_BLOCK_SIZE];
    sm3_ctx_t ctx;
    int i;

    memset(key_block, 0, SM3_BLOCK_SIZE);

    if (key_len > SM3_BLOCK_SIZE) {
        /* Key is too long — hash it first */
        sm3_hash(key, key_len, key_block);
        /* key_block now contains 32 bytes of hash, rest is already zero */
    } else {
        memcpy(key_block, key, key_len);
    }

    /* Inner: H((K ^ ipad) || msg) */
    uint8_t ipad[SM3_BLOCK_SIZE];
    for (i = 0; i < SM3_BLOCK_SIZE; i++) ipad[i] = key_block[i] ^ 0x36;

    sm3_init(&ctx);
    sm3_update(&ctx, ipad, SM3_BLOCK_SIZE);
    sm3_update(&ctx, msg, msg_len);
    uint8_t inner_hash[SM3_DIGEST_SIZE];
    sm3_final(&ctx, inner_hash);

    /* Outer: H((K ^ opad) || inner_hash) */
    uint8_t opad[SM3_BLOCK_SIZE];
    for (i = 0; i < SM3_BLOCK_SIZE; i++) opad[i] = key_block[i] ^ 0x5C;

    sm3_init(&ctx);
    sm3_update(&ctx, opad, SM3_BLOCK_SIZE);
    sm3_update(&ctx, inner_hash, SM3_DIGEST_SIZE);
    sm3_final(&ctx, mac);
}
