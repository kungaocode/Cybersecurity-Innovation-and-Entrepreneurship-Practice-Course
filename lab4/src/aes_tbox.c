/*
 * AES Experiment — T-table implementation
 *
 * Combines SubBytes + ShiftRows + MixColumns into four 1KB lookup tables
 * (Te0..Te3). Each round becomes 4 table lookups + 4 XORs per column.
 * Significantly faster than the basic S-box approach.
 */

#include "aes_internal.h"

/* ─── Key expansion for T-table (same as S-box) ─── */

static int aes_tbox_set_encrypt_key(AES_Key *ctx, const uint8_t *key, int key_len)
{
    const int Nk = key_len / 4;
    ctx->rounds = Nk + 6;

    uint32_t *rk = ctx->rk;
    for (int i = 0; i < Nk; i++)
        rk[i] = LOAD_U32_BE(key + 4 * i);

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

/* ─── T-table encrypt ─── */

void AES_TBOX_EncryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out)
{
    const uint32_t *rk = ctx->rk;
    uint32_t s0, s1, s2, s3, t0 = 0, t1 = 0, t2 = 0, t3 = 0;

    /* Initial AddRoundKey */
    s0 = LOAD_U32_BE(in +  0) ^ rk[0];
    s1 = LOAD_U32_BE(in +  4) ^ rk[1];
    s2 = LOAD_U32_BE(in +  8) ^ rk[2];
    s3 = LOAD_U32_BE(in + 12) ^ rk[3];

    /* Rounds 1..rounds-1 using T-tables */
    int r;
    for (r = 1; r < ctx->rounds; r++) {
        t0 = AES_TE0[(s0 >> 24)       ] ^ AES_TE1[(s1 >> 16) & 0xFF] ^
             AES_TE2[(s2 >>  8) & 0xFF] ^ AES_TE3[ s3        & 0xFF] ^ rk[4 * r + 0];
        t1 = AES_TE0[(s1 >> 24)       ] ^ AES_TE1[(s2 >> 16) & 0xFF] ^
             AES_TE2[(s3 >>  8) & 0xFF] ^ AES_TE3[ s0        & 0xFF] ^ rk[4 * r + 1];
        t2 = AES_TE0[(s2 >> 24)       ] ^ AES_TE1[(s3 >> 16) & 0xFF] ^
             AES_TE2[(s0 >>  8) & 0xFF] ^ AES_TE3[ s1        & 0xFF] ^ rk[4 * r + 2];
        t3 = AES_TE0[(s3 >> 24)       ] ^ AES_TE1[(s0 >> 16) & 0xFF] ^
             AES_TE2[(s1 >>  8) & 0xFF] ^ AES_TE3[ s2        & 0xFF] ^ rk[4 * r + 3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    /* Last round: SubBytes + ShiftRows only (no MixColumns), using S-box */
    rk += ctx->rounds * 4;
    s0 = (AES_SBOX[(t0 >> 24)       ] << 24) ^ (AES_SBOX[(t1 >> 16) & 0xFF] << 16) ^
         (AES_SBOX[(t2 >>  8) & 0xFF] <<  8) ^ (AES_SBOX[ t3        & 0xFF]      ) ^ rk[0];
    s1 = (AES_SBOX[(t1 >> 24)       ] << 24) ^ (AES_SBOX[(t2 >> 16) & 0xFF] << 16) ^
         (AES_SBOX[(t3 >>  8) & 0xFF] <<  8) ^ (AES_SBOX[ t0        & 0xFF]      ) ^ rk[1];
    s2 = (AES_SBOX[(t2 >> 24)       ] << 24) ^ (AES_SBOX[(t3 >> 16) & 0xFF] << 16) ^
         (AES_SBOX[(t0 >>  8) & 0xFF] <<  8) ^ (AES_SBOX[ t1        & 0xFF]      ) ^ rk[2];
    s3 = (AES_SBOX[(t3 >> 24)       ] << 24) ^ (AES_SBOX[(t0 >> 16) & 0xFF] << 16) ^
         (AES_SBOX[(t1 >>  8) & 0xFF] <<  8) ^ (AES_SBOX[ t2        & 0xFF]      ) ^ rk[3];

    STORE_U32_BE(out +  0, s0);
    STORE_U32_BE(out +  4, s1);
    STORE_U32_BE(out +  8, s2);
    STORE_U32_BE(out + 12, s3);
}

/* ─── T-table decrypt ─── */

void AES_TBOX_DecryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out)
{
    const uint32_t *rk = ctx->rk;
    uint32_t s0, s1, s2, s3, t0 = 0, t1 = 0, t2 = 0, t3 = 0;

    /* Initial AddRoundKey with last round key */
    s0 = LOAD_U32_BE(in +  0) ^ rk[4 * ctx->rounds + 0];
    s1 = LOAD_U32_BE(in +  4) ^ rk[4 * ctx->rounds + 1];
    s2 = LOAD_U32_BE(in +  8) ^ rk[4 * ctx->rounds + 2];
    s3 = LOAD_U32_BE(in + 12) ^ rk[4 * ctx->rounds + 3];

    for (int r = ctx->rounds - 1; r > 0; r--) {
        t0 = AES_TD0[(s0 >> 24)       ] ^ AES_TD1[(s3 >> 16) & 0xFF] ^
             AES_TD2[(s2 >>  8) & 0xFF] ^ AES_TD3[ s1        & 0xFF] ^ rk[4 * r + 0];
        t1 = AES_TD0[(s1 >> 24)       ] ^ AES_TD1[(s0 >> 16) & 0xFF] ^
             AES_TD2[(s3 >>  8) & 0xFF] ^ AES_TD3[ s2        & 0xFF] ^ rk[4 * r + 1];
        t2 = AES_TD0[(s2 >> 24)       ] ^ AES_TD1[(s1 >> 16) & 0xFF] ^
             AES_TD2[(s0 >>  8) & 0xFF] ^ AES_TD3[ s3        & 0xFF] ^ rk[4 * r + 2];
        t3 = AES_TD0[(s3 >> 24)       ] ^ AES_TD1[(s2 >> 16) & 0xFF] ^
             AES_TD2[(s1 >>  8) & 0xFF] ^ AES_TD3[ s0        & 0xFF] ^ rk[4 * r + 3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    /* Last round: InvSubBytes + InvShiftRows only */
    s0 = (AES_INV_SBOX[(t0 >> 24)       ] << 24) ^ (AES_INV_SBOX[(t3 >> 16) & 0xFF] << 16) ^
         (AES_INV_SBOX[(t2 >>  8) & 0xFF] <<  8) ^ (AES_INV_SBOX[ t1        & 0xFF]      ) ^ rk[0];
    s1 = (AES_INV_SBOX[(t1 >> 24)       ] << 24) ^ (AES_INV_SBOX[(t0 >> 16) & 0xFF] << 16) ^
         (AES_INV_SBOX[(t3 >>  8) & 0xFF] <<  8) ^ (AES_INV_SBOX[ t2        & 0xFF]      ) ^ rk[1];
    s2 = (AES_INV_SBOX[(t2 >> 24)       ] << 24) ^ (AES_INV_SBOX[(t1 >> 16) & 0xFF] << 16) ^
         (AES_INV_SBOX[(t0 >>  8) & 0xFF] <<  8) ^ (AES_INV_SBOX[ t3        & 0xFF]      ) ^ rk[2];
    s3 = (AES_INV_SBOX[(t3 >> 24)       ] << 24) ^ (AES_INV_SBOX[(t2 >> 16) & 0xFF] << 16) ^
         (AES_INV_SBOX[(t1 >>  8) & 0xFF] <<  8) ^ (AES_INV_SBOX[ t0        & 0xFF]      ) ^ rk[3];

    STORE_U32_BE(out +  0, s0);
    STORE_U32_BE(out +  4, s1);
    STORE_U32_BE(out +  8, s2);
    STORE_U32_BE(out + 12, s3);
}
