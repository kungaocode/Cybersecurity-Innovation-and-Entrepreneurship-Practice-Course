/*
 * AES Experiment — Working mode implementations: CTR, GCM, XTS
 *
 * References:
 *   NIST SP 800-38A (CTR)
 *   NIST SP 800-38D (GCM)
 *   IEEE Std 1619-2007 (XTS)
 */

#include "aes_internal.h"
#include <string.h>
#include <stdio.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * CTR (Counter) Mode  —  NIST SP 800-38A
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * CTR turns a block cipher into a stream cipher. The counter is encrypted
 * and the result is XORed with the plaintext/ciphertext.
 */

void AES_CTR_Encrypt(const AES_Key *ctx, const uint8_t *in, uint8_t *out,
                     uint32_t len, uint8_t *iv,
                     aes_encrypt_block_fn enc_fn)
{
    uint8_t counter[AES_BLOCK_SIZE];
    uint8_t keystream[AES_BLOCK_SIZE];
    memcpy(counter, iv, AES_BLOCK_SIZE);

    while (len > 0) {
        enc_fn(ctx, counter, keystream);

        uint32_t n = (len < AES_BLOCK_SIZE) ? len : AES_BLOCK_SIZE;
        for (uint32_t i = 0; i < n; i++)
            out[i] = in[i] ^ keystream[i];

        /* Increment counter (big-endian, 128-bit) */
        for (int i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }

        in  += n;
        out += n;
        len -= n;
    }

    /* Update IV with final counter value */
    memcpy(iv, counter, AES_BLOCK_SIZE);
    aes_cleanse(keystream, sizeof(keystream));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * GCM (Galois/Counter Mode)  —  NIST SP 800-38D
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * GCM = CTR-mode encryption + GHASH authentication.
 *
 * GHASH computes:  X_i = (X_{i-1} ⊕ A_i) • H
 * where • is multiplication in GF(2^128) with polynomial:
 *   x^128 + x^7 + x^2 + x + 1
 *
 * We use a table-driven approach: precompute H·x^i for i in 0..127,
 * organized as 16 tables of 16 entries each for 4-bit indexed lookup.
 */

/* ─── GF(2^128) helpers ─── */

typedef struct {
    uint64_t lo, hi;
} gf128;

static inline gf128 gf128_zero(void)
{
    gf128 r = {0, 0};
    return r;
}

static inline void gf128_xor(gf128 *a, const gf128 *b)
{
    a->lo ^= b->lo;
    a->hi ^= b->hi;
}

/* Load a gf128 from a 16-byte big-endian buffer */
static gf128 gf128_load(const uint8_t *p)
{
    gf128 r;
    r.hi = LOAD_U32_BE(p) | ((uint64_t)LOAD_U32_BE(p + 4) << 32);
    r.lo = LOAD_U32_BE(p + 8) | ((uint64_t)LOAD_U32_BE(p + 12) << 32);
    /* Swap hi/lo to match the bit-ordering convention:
     * We store as (high 64 bits, low 64 bits) where byte 0 is the MSB.
     * So hi gets bytes 0-7 (big-endian), lo gets bytes 8-15.
     */
    return r;
}

/* Store a gf128 to a 16-byte big-endian buffer */
static void gf128_store(uint8_t *p, const gf128 *r)
{
    STORE_U32_BE(p,     (uint32_t)(r->hi >> 32));
    STORE_U32_BE(p + 4, (uint32_t)(r->hi));
    STORE_U32_BE(p + 8, (uint32_t)(r->lo >> 32));
    STORE_U32_BE(p + 12,(uint32_t)(r->lo));
}

/*
 * GCM uses a specific bit ordering: the leftmost bit is the coefficient
 * of the highest-degree term. This means byte 0 bit 0 is x^127,
 * and byte 15 bit 7 is x^0. Our gf128 representation stores the value
 * as (hi << 64 | lo) where hi corresponds to the first 8 bytes and
 * lo to the last 8 bytes (in big-endian order).
 *
 * Polynomial reduction: R = 0xE1 << (128 - 8) = 0xE100000000000000 (in MSB of hi)
 * Actually R = 11100001 << 120
 */

/*
 * Simple bit-reflected GF(2^128) multiply (GCM right-shift variant).
 * Polynomial: x^128 + x^7 + x^2 + x + 1.
 * In the reflected domain, reduction constant R = 0xE1 << 120.
 */
static void gcm_gf128_mul(gf128 *x, const gf128 *y)
{
    /*
     * GCM uses the polynomial x^128 + x^7 + x^2 + x + 1.
     * In the standard (non-reflected) domain, reduction after left-shift:
     *   if carry: x ^= 0xE1 (which is x^7 + x^2 + x + 1)
     *   This is: R = 0xE1 << 120 for 128-bit shift (but R is only 8 bits...)
     *
     * Wait, let me reconsider. The reducing polynomial is:
     *   P(x) = x^128 + x^7 + x^2 + x + 1
     *
     * When we multiply in GF(2^128), after each left shift, if bit 127 was 1,
     * we XOR with P(x) (after shifting, bit 128 is set, so XOR with P clears it).
     * Since P = x^128 + lower terms, XOR with P (after shift) means:
     *   result ^= (x^7 + x^2 + x + 1) = 0x87.
     *
     * But the polynomial's low 128 bits (after masking) are: 0x87.
     * So: if (v.hi >> 63): v.hi ^= 0x87 (in the low byte of hi).
     *
     * Actually, let's be precise. The value is 128 bits stored as (hi:lo)
     * where hi is the upper 64 bits. Bit 127 is (hi >> 63).
     * After left shift, bit 127 moves to bit 128 (which is the LSB of what
     * would be the next 64-bit word). We XOR the low 128 bits with
     * (0x87 << 0) = 0x87, which affects bits 0-7 of `lo`.
     *
     * So: carry = (v.hi >> 63); v.hi <<= 1; v.hi |= (v.lo >> 63); v.lo <<= 1;
     *     if (carry) v.lo ^= 0x87;
     *
     * But wait, the standard NIST GCM uses a different variant. Let me check.
     *
     * In GCM, Ghash is defined as:
     *   X_{i} = (X_{i-1} ⊕ A_i) • H
     *
     * The multiplication is in GF(2^128) with the polynomial.
     * Most implementations use the right-shift variant:
     *   if (V & 1) Z ^= X;
     *   V >>= 1;
     *   if (X & 1) X = (X >> 1) ^ R; else X >>= 1;
     * where R = 0xE1000000000000000000000000000000 (i.e., 0xE1 << 120)
     *
     * This is the "reflected" or "little-endian" approach.
     */

    uint64_t z[2] = {0, 0};
    uint64_t v[2] = {y->lo, y->hi};
    uint64_t xx[2] = {x->lo, x->hi};

    for (int i = 0; i < 128; i++) {
        if (v[0] & 1) {
            z[0] ^= xx[0];
            z[1] ^= xx[1];
        }
        uint64_t carry = (xx[1] & 1) ? 0xE100000000000000ULL : 0ULL;
        xx[1] = (xx[0] << 63) | (xx[1] >> 1);
        xx[0] = (xx[0] >> 1) ^ carry;
        v[0] = (v[1] << 63) | (v[0] >> 1);
        v[1] >>= 1;
    }

    x->lo = z[0];
    x->hi = z[1];
}

/* ─── GHASH implementation ─── */

/*
 * Precompute M[i][j] = j * (H * x^(4*i)) for 4-bit table lookup.
 * This uses 64 tables × 16 entries × 16 bytes = 16KB.
 *
 * For a simpler and more portable implementation, we use the shift-and-XOR
 * method directly (no precomputation), accepting the performance cost.
 * GCM performance is dominated by the block cipher, not GHASH, for
 * typical message sizes.
 */

typedef struct {
    gf128 H;      /* hash subkey */
    gf128 X;      /* current GHASH state */
} GHASH_CTX;

static void ghash_init(GHASH_CTX *gctx, const uint8_t *H_block)
{
    gctx->H = gf128_load(H_block);
    gctx->X = gf128_zero();
}

static void ghash_update(GHASH_CTX *gctx, const uint8_t *data, uint32_t len)
{
    /* Process 16-byte blocks */
    while (len >= 16) {
        gf128 block = gf128_load(data);
        gf128_xor(&gctx->X, &block);
        gcm_gf128_mul(&gctx->X, &gctx->H);
        data += 16;
        len -= 16;
    }

    /* Process partial final block */
    if (len > 0) {
        uint8_t pad[16] = {0};
        memcpy(pad, data, len);
        gf128 block = gf128_load(pad);
        gf128_xor(&gctx->X, &block);
        gcm_gf128_mul(&gctx->X, &gctx->H);
        aes_cleanse(pad, 16);
    }
}

static void ghash_final(GHASH_CTX *gctx, const uint8_t *data, uint32_t len,
                        uint64_t aad_bits, uint64_t ct_bits, uint8_t *tag)
{
    /* Process remaining data (if any) */
    ghash_update(gctx, data, len);

    /* Append lengths block: [len(AAD) || len(C)] each as 64-bit big-endian */
    uint8_t len_block[16] = {0};
    STORE_U32_BE(len_block,     (uint32_t)(aad_bits >> 32));
    STORE_U32_BE(len_block + 4, (uint32_t)(aad_bits));
    STORE_U32_BE(len_block + 8, (uint32_t)(ct_bits >> 32));
    STORE_U32_BE(len_block + 12,(uint32_t)(ct_bits));

    gf128 lblock = gf128_load(len_block);
    gf128_xor(&gctx->X, &lblock);
    gcm_gf128_mul(&gctx->X, &gctx->H);

    gf128_store(tag, &gctx->X);
}

/* ─── GCM public API ─── */

int AES_GCM_Encrypt(const AES_Key *ctx, const uint8_t *in, uint8_t *out,
                    uint32_t len, const uint8_t *iv, uint32_t iv_len,
                    const uint8_t *aad, uint32_t aad_len,
                    uint8_t *tag, uint32_t tag_len,
                    aes_encrypt_block_fn enc_fn)
{
    /* Derive hash subkey H = AES_K(0^128) */
    uint8_t H_block[16] = {0};
    enc_fn(ctx, H_block, H_block);

    GHASH_CTX gctx;
    ghash_init(&gctx, H_block);

    /* GHASH over AAD */
    ghash_update(&gctx, aad, aad_len);

    /* Build initial counter block J0 */
    uint8_t J0[16];
    if (iv_len == 12) {
        /* IV || 0^31 || 1 */
        memcpy(J0, iv, 12);
        J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
    } else {
        /* J0 = GHASH(IV || 0^s || len(IV)_64) */
        GHASH_CTX iv_ctx;
        ghash_init(&iv_ctx, H_block);
        ghash_final(&iv_ctx, iv, iv_len, 0, (uint64_t)iv_len * 8, J0);
    }

    /* CTR encryption starting at J0+1 for plaintext, J0 for tag */
    uint8_t counter[16];
    memcpy(counter, J0, 16);

    /* Increment counter for the first plaintext block */
    for (int i = 15; i >= 0; i--)
        if (++counter[i] != 0) break;

    /* Encrypt plaintext */
    AES_CTR_Encrypt(ctx, in, out, len, counter, enc_fn);

    /* GHASH over ciphertext */
    ghash_update(&gctx, out, len);

    /* Finalize GHASH with lengths */
    uint8_t S[16];
    ghash_final(&gctx, NULL, 0, (uint64_t)aad_len * 8, (uint64_t)len * 8, S);

    /* Tag = GHASH_final XOR AES_K(J0) */
    uint8_t Ek_J0[16];
    enc_fn(ctx, J0, Ek_J0);
    for (uint32_t i = 0; i < tag_len && i < 16; i++)
        tag[i] = S[i] ^ Ek_J0[i];

    aes_cleanse(S, 16);
    aes_cleanse(Ek_J0, 16);
    aes_cleanse(H_block, 16);
    aes_cleanse(&gctx, sizeof(gctx));
    return 0;
}

int AES_GCM_Decrypt(const AES_Key *ctx, const uint8_t *in, uint8_t *out,
                    uint32_t len, const uint8_t *iv, uint32_t iv_len,
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *tag, uint32_t tag_len,
                    aes_encrypt_block_fn enc_fn)
{
    /* Derive hash subkey H = AES_K(0^128) */
    uint8_t H_block[16] = {0};
    enc_fn(ctx, H_block, H_block);

    GHASH_CTX gctx;
    ghash_init(&gctx, H_block);

    /* GHASH over AAD */
    ghash_update(&gctx, aad, aad_len);

    /* Build J0 */
    uint8_t J0[16];
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
    } else {
        GHASH_CTX iv_ctx;
        ghash_init(&iv_ctx, H_block);
        ghash_final(&iv_ctx, iv, iv_len, 0, (uint64_t)iv_len * 8, J0);
    }

    /* GHASH over ciphertext BEFORE decryption */
    ghash_update(&gctx, in, len);

    /* Finalize GHASH to get expected tag */
    uint8_t expected_tag[16];
    ghash_final(&gctx, NULL, 0, (uint64_t)aad_len * 8, (uint64_t)len * 8, expected_tag);
    uint8_t Ek_J0[16];
    enc_fn(ctx, J0, Ek_J0);
    for (int i = 0; i < 16; i++)
        expected_tag[i] ^= Ek_J0[i];

    /* Verify tag (constant-time comparison) */
    uint8_t diff = 0;
    for (uint32_t i = 0; i < tag_len && i < 16; i++)
        diff |= (expected_tag[i] ^ tag[i]);
    for (uint32_t i = tag_len; i < 16; i++)
        diff |= expected_tag[i];  /* remaining bytes should be 0 */

    if (diff != 0) {
        aes_cleanse(out, len);
        aes_cleanse(expected_tag, 16);
        aes_cleanse(&gctx, sizeof(gctx));
        return -1;  /* authentication failed */
    }

    /* CTR decryption */
    uint8_t counter[16];
    memcpy(counter, J0, 16);
    for (int i = 15; i >= 0; i--)
        if (++counter[i] != 0) break;

    AES_CTR_Encrypt(ctx, in, out, len, counter, enc_fn);

    aes_cleanse(expected_tag, 16);
    aes_cleanse(Ek_J0, 16);
    aes_cleanse(H_block, 16);
    aes_cleanse(&gctx, sizeof(gctx));
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * XTS (XEX-based tweaked-codebook mode with ciphertext stealing)
 * IEEE Std 1619-2007
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * XTS uses two independent AES keys (key1, key2).
 * For each data unit (sector):
 *   T = AES_Encrypt(key2, tweak)   (the tweak is typically the sector number)
 *   For j = 0 to m-2:
 *     PP = P_j ⊕ T
 *     CC = AES_Encrypt(key1, PP)
 *     C_j = CC ⊕ T
 *     T = T ⊗ α   (GF(2^128) multiplication by α = x)
 *   Ciphertext stealing for the last two blocks.
 *
 * GF(2^128) multiplication by α (primitive element x):
 *   T = T << 1, if carry then T ^= 0x87
 */

static void xts_gf128_mul_alpha(uint8_t *t)
{
    uint8_t carry = 0;
    uint8_t new_carry;
    for (int i = 0; i < 16; i++) {
        new_carry = t[i] >> 7;
        t[i] = (t[i] << 1) | carry;
        carry = new_carry;
    }
    if (carry)
        t[0] ^= 0x87;  /* reduction polynomial (little-endian byte 0) */
}

void AES_XTS_Encrypt(const AES_Key *key_data, const AES_Key *key_tweak,
                     const uint8_t *in, uint8_t *out, uint32_t len,
                     const uint8_t *tweak, aes_encrypt_block_fn enc_fn)
{
    if (len < AES_BLOCK_SIZE) return;

    /* T = AES_Encrypt(key_tweak, tweak) */
    uint8_t T[AES_BLOCK_SIZE];
    enc_fn(key_tweak, tweak, T);

    uint32_t num_blocks = len / AES_BLOCK_SIZE;
    uint32_t remainder  = len % AES_BLOCK_SIZE;

    /* Process all full blocks (or all but the last if there's a remainder) */
    uint32_t blocks = num_blocks;
    if (remainder > 0 && num_blocks >= 1) {
        /* Ciphertext stealing: process n-2 full blocks, then steal */
        if (num_blocks >= 2)
            blocks = num_blocks - 2;
        else
            blocks = 0;
    }

    for (uint32_t j = 0; j < blocks; j++) {
        uint8_t PP[AES_BLOCK_SIZE];
        for (int i = 0; i < AES_BLOCK_SIZE; i++)
            PP[i] = in[i] ^ T[i];
        uint8_t CC[AES_BLOCK_SIZE];
        enc_fn(key_data, PP, CC);
        for (int i = 0; i < AES_BLOCK_SIZE; i++)
            out[i] = CC[i] ^ T[i];
        xts_gf128_mul_alpha(T);
        in  += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }

    if (remainder > 0) {
        /* Ciphertext stealing */
        uint8_t PP[AES_BLOCK_SIZE], CC[AES_BLOCK_SIZE];
        uint8_t T_next[AES_BLOCK_SIZE];
        memcpy(T_next, T, AES_BLOCK_SIZE);
        xts_gf128_mul_alpha(T_next);

        if (num_blocks >= 1) {
            /* Encrypt the last full block */
            for (int i = 0; i < AES_BLOCK_SIZE; i++)
                PP[i] = in[(num_blocks - 1) * AES_BLOCK_SIZE + i] ^ T[i];
            enc_fn(key_data, PP, CC);

            /* The output for the partial block comes from CC */
            for (uint32_t i = 0; i < remainder; i++)
                out[num_blocks * AES_BLOCK_SIZE + i] = CC[i] ^ T_next[i];

            /* Build the penultimate input: partial data padded with CC's tail */
            for (uint32_t i = 0; i < remainder; i++)
                PP[i] = in[num_blocks * AES_BLOCK_SIZE + i] ^ T_next[i];
            for (uint32_t i = remainder; i < AES_BLOCK_SIZE; i++)
                PP[i] = CC[i] ^ T_next[i];

            uint8_t CC2[AES_BLOCK_SIZE];
            enc_fn(key_data, PP, CC2);
            for (int i = 0; i < AES_BLOCK_SIZE; i++)
                out[(num_blocks - 1) * AES_BLOCK_SIZE + i] = CC2[i] ^ T[i];
        } else {
            /* Only partial data (len < 16); XOR with encrypted tweak */
            enc_fn(key_tweak, T, CC);
            for (uint32_t i = 0; i < remainder; i++)
                out[i] = in[i] ^ CC[i];
        }
    } else if (remainder == 0 && num_blocks > 0) {
        /* No remainder — process remaining blocks (if any) */
    }
}

void AES_XTS_Decrypt(const AES_Key *key_data, const AES_Key *key_tweak,
                     const uint8_t *in, uint8_t *out, uint32_t len,
                     const uint8_t *tweak,
                     aes_encrypt_block_fn enc_fn, aes_decrypt_block_fn dec_fn)
{
    if (len < AES_BLOCK_SIZE) return;

    /* T = AES_Encrypt(key_tweak, tweak) */
    uint8_t T[AES_BLOCK_SIZE];
    enc_fn(key_tweak, tweak, T);

    uint32_t num_blocks = len / AES_BLOCK_SIZE;
    uint32_t remainder  = len % AES_BLOCK_SIZE;

    uint32_t blocks = num_blocks;
    if (remainder > 0 && num_blocks >= 1) {
        if (num_blocks >= 2)
            blocks = num_blocks - 2;
        else
            blocks = 0;
    }

    for (uint32_t j = 0; j < blocks; j++) {
        uint8_t CC[AES_BLOCK_SIZE];
        for (int i = 0; i < AES_BLOCK_SIZE; i++)
            CC[i] = in[i] ^ T[i];
        uint8_t PP[AES_BLOCK_SIZE];
        dec_fn(key_data, CC, PP);
        for (int i = 0; i < AES_BLOCK_SIZE; i++)
            out[i] = PP[i] ^ T[i];
        xts_gf128_mul_alpha(T);
        in  += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }

    if (remainder > 0) {
        uint8_t PP[AES_BLOCK_SIZE], CC[AES_BLOCK_SIZE];
        uint8_t T_next[AES_BLOCK_SIZE];
        memcpy(T_next, T, AES_BLOCK_SIZE);
        xts_gf128_mul_alpha(T_next);

        if (num_blocks >= 1) {
            /* Decrypt the penultimate block (output of CTS encrypt) */
            for (int i = 0; i < AES_BLOCK_SIZE; i++)
                CC[i] = in[(num_blocks - 1) * AES_BLOCK_SIZE + i] ^ T[i];
            dec_fn(key_data, CC, PP);

            /* Partial block output from decrypted penultimate block */
            for (uint32_t i = 0; i < remainder; i++)
                out[num_blocks * AES_BLOCK_SIZE + i] = PP[i] ^ T_next[i];

            /* Reconstruct the ciphertext for the last full block:
             * partial ciphertext || tail of penultimate plaintext */
            for (uint32_t i = 0; i < remainder; i++)
                CC[i] = in[num_blocks * AES_BLOCK_SIZE + i] ^ T_next[i];
            for (uint32_t i = remainder; i < AES_BLOCK_SIZE; i++)
                CC[i] = PP[i] ^ T_next[i];

            uint8_t PP2[AES_BLOCK_SIZE];
            dec_fn(key_data, CC, PP2);
            for (int i = 0; i < AES_BLOCK_SIZE; i++)
                out[(num_blocks - 1) * AES_BLOCK_SIZE + i] = PP2[i] ^ T[i];
        } else {
            enc_fn(key_tweak, T, CC);
            for (uint32_t i = 0; i < remainder; i++)
                out[i] = in[i] ^ CC[i];
        }
    }
}

/* ─── Method name helper ─── */

const char *AES_MethodName(int method)
{
    switch (method) {
        case AES_METHOD_SBOX:    return "S-box (basic scalar)";
        case AES_METHOD_TBOX:    return "T-table";
        case AES_METHOD_SHUFFLE: return "SIMD shuffle (SSSE3)";
        case AES_METHOD_NI:      return "AES-NI (hardware)";
        default:                 return "Unknown";
    }
}
