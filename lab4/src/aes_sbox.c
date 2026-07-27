/*
 * AES Experiment — Basic S-box implementation (scalar, educational baseline)
 *
 * Each AES round step is performed separately:
 *   SubBytes → ShiftRows → MixColumns → AddRoundKey
 *
 * This is the slowest method and serves as the baseline for comparison.
 */

#include "aes_internal.h"

/* ─── Key expansion (scalar, uses S-box) ─── */

static int aes_sbox_set_encrypt_key(AES_Key *ctx, const uint8_t *key, int key_len)
{
    const int Nk = key_len / 4;           /* key words */
    ctx->rounds = Nk + 6;                 /* 10, 12, or 14 */

    uint32_t *rk = ctx->rk;
    for (int i = 0; i < Nk; i++) {
        rk[i] = LOAD_U32_BE(key + 4 * i);
    }

    for (int i = Nk; i < 4 * (ctx->rounds + 1); i++) {
        uint32_t t = rk[i - 1];
        if ((i % Nk) == 0) {
            t = AES_SUB_WORD(ROTL32(t, 8)) ^ AES_RCON[i / Nk - 1];
        } else if (Nk > 6 && (i % Nk) == 4) {
            t = AES_SUB_WORD(t);
        }
        rk[i] = rk[i - Nk] ^ t;
    }
    return 0;
}

static int aes_sbox_set_decrypt_key(AES_Key *ctx, const uint8_t *key, int key_len)
{
    /* First expand the encryption key */
    int ret = aes_sbox_set_encrypt_key(ctx, key, key_len);
    if (ret != 0) return ret;

    /* Then invert MixColumns for rounds 1..rounds-1 */
    uint32_t *rk = ctx->rk;
    for (int r = 1; r < ctx->rounds; r++) {
        uint32_t *rp = rk + 4 * r;
        for (int j = 0; j < 4; j++) {
            uint32_t w = rp[j];
            rp[j] = AES_TD0[AES_SBOX[(w >> 24)       ]] ^
                    AES_TD1[AES_SBOX[(w >> 16) & 0xFF]] ^
                    AES_TD2[AES_SBOX[(w >>  8) & 0xFF]] ^
                    AES_TD3[AES_SBOX[ w        & 0xFF]];
        }
    }
    return 0;
}

/* ─── Round helpers ─── */

static void add_round_key(uint32_t *s, const uint32_t *rk, int round)
{
    for (int i = 0; i < 4; i++)
        s[i] ^= rk[4 * round + i];
}

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

static void shift_rows(uint32_t *s)
{
    uint32_t t[4];
    for (int i = 0; i < 4; i++) t[i] = s[i];
    s[0] = (t[0] & 0xFF000000) | (t[1] & 0x00FF0000) | (t[2] & 0x0000FF00) | (t[3] & 0x000000FF);
    s[1] = (t[1] & 0xFF000000) | (t[2] & 0x00FF0000) | (t[3] & 0x0000FF00) | (t[0] & 0x000000FF);
    s[2] = (t[2] & 0xFF000000) | (t[3] & 0x00FF0000) | (t[0] & 0x0000FF00) | (t[1] & 0x000000FF);
    s[3] = (t[3] & 0xFF000000) | (t[0] & 0x00FF0000) | (t[1] & 0x0000FF00) | (t[2] & 0x000000FF);
}

static void inv_shift_rows(uint32_t *s)
{
    uint32_t t[4];
    for (int i = 0; i < 4; i++) t[i] = s[i];
    s[0] = (t[0] & 0xFF000000) | (t[3] & 0x00FF0000) | (t[2] & 0x0000FF00) | (t[1] & 0x000000FF);
    s[1] = (t[1] & 0xFF000000) | (t[0] & 0x00FF0000) | (t[3] & 0x0000FF00) | (t[2] & 0x000000FF);
    s[2] = (t[2] & 0xFF000000) | (t[1] & 0x00FF0000) | (t[0] & 0x0000FF00) | (t[3] & 0x000000FF);
    s[3] = (t[3] & 0xFF000000) | (t[2] & 0x00FF0000) | (t[1] & 0x0000FF00) | (t[0] & 0x000000FF);
}

/* GF(2^8) multiplication helpers */
static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
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

static void mix_columns(uint32_t *s, int encrypt)
{
    /* Matrix: encrypt → [2,3,1,1; 1,2,3,1; 1,1,2,3; 3,1,1,2]
     *         decrypt → [0e,0b,0d,09; 09,0e,0b,0d; 0d,09,0e,0b; 0b,0d,09,0e] */
    uint8_t a[4][4], b[4][4];

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            a[i][j] = (uint8_t)(s[i] >> (24 - 8 * j));

    /* a[col][row] = byte at (row, col); b[new_row][col] = result */
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

    /* Store back: s[col] = [row0,col | row1,col | row2,col | row3,col] */
    for (int i = 0; i < 4; i++) {
        s[i] = ((uint32_t)b[0][i] << 24) | ((uint32_t)b[1][i] << 16) |
               ((uint32_t)b[2][i] <<  8) | ((uint32_t)b[3][i]);
    }
}

/* ─── Public API ─── */

int AES_SetEncryptKey(AES_Key *ctx, const uint8_t *key, int key_len_bytes)
{
    if (!ctx || !key) return -1;
    return aes_sbox_set_encrypt_key(ctx, key, key_len_bytes);
}

int AES_SetDecryptKey(AES_Key *ctx, const uint8_t *key, int key_len_bytes)
{
    if (!ctx || !key) return -1;
    return aes_sbox_set_decrypt_key(ctx, key, key_len_bytes);
}

void AES_CleanKey(AES_Key *ctx)
{
    if (ctx) aes_cleanse(ctx, sizeof(*ctx));
}

void AES_SBOX_EncryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t s[4];
    for (int i = 0; i < 4; i++)
        s[i] = LOAD_U32_BE(in + 4 * i);

    add_round_key(s, ctx->rk, 0);
    for (int r = 1; r < ctx->rounds; r++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s, 1);
        add_round_key(s, ctx->rk, r);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, ctx->rk, ctx->rounds);

    for (int i = 0; i < 4; i++)
        STORE_U32_BE(out + 4 * i, s[i]);
}

void AES_SBOX_DecryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t s[4];
    for (int i = 0; i < 4; i++)
        s[i] = LOAD_U32_BE(in + 4 * i);

    /* Equivalent inverse cipher per FIPS 197 Section 5.3.5 */
    add_round_key(s, ctx->rk, ctx->rounds);  /* dw[Nr] = w[Nr] */
    for (int r = ctx->rounds - 1; r > 0; r--) {
        inv_sub_bytes(s);
        inv_shift_rows(s);
        mix_columns(s, 0);  /* InvMixColumns */
        add_round_key(s, ctx->rk, r);  /* dw[r] = InvMixColumns(w[r]) */
    }
    inv_sub_bytes(s);
    inv_shift_rows(s);
    add_round_key(s, ctx->rk, 0);  /* dw[0] = w[0] */

    for (int i = 0; i < 4; i++)
        STORE_U32_BE(out + 4 * i, s[i]);
}
