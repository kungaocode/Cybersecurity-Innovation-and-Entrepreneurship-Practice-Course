/*
 * AES Experiment - Self-contained header
 *
 * Software implementation of AES symmetric cipher with multiple optimization
 * methods: S-box, T-table, SIMD shuffle (PSHUFB), and AES-NI.
 * Working modes: CTR, GCM, XTS.
 */

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AES block size is always 16 bytes */
#define AES_BLOCK_SIZE      16
#define AES_MAX_ROUNDS      14
#define AES_MAX_RK_WORDS    (4 * (AES_MAX_ROUNDS + 1))  /* 60 */

/*
 * Unified AES key structure.
 * For AES-NI, we also keep an __m128i version (see aes_ni.c internal).
 */
typedef struct {
    uint32_t rk[AES_MAX_RK_WORDS];  /* expanded round keys */
    int      rounds;                 /* 10, 12, or 14 */
} AES_Key;

/* ─── Key setup ─── */
int AES_SetEncryptKey(AES_Key *ctx, const uint8_t *key, int key_len_bytes);
int AES_SetDecryptKey(AES_Key *ctx, const uint8_t *key, int key_len_bytes);
void AES_CleanKey(AES_Key *ctx);

/* ─── Single-block encrypt/decrypt ─── */
/* Dispatch through function pointers; each method also exposes its own entry. */
typedef void (*aes_encrypt_block_fn)(const AES_Key *ctx, const uint8_t *in, uint8_t *out);
typedef void (*aes_decrypt_block_fn)(const AES_Key *ctx, const uint8_t *in, uint8_t *out);

/* S-box method (basic scalar) */
void AES_SBOX_EncryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out);
void AES_SBOX_DecryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out);

/* T-table method */
void AES_TBOX_EncryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out);
void AES_TBOX_DecryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out);

/* SIMD shuffle method (SSSE3) — returns 0 on success, -1 if unavailable */
int  AES_SHUFFLE_EncryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out);
int  AES_SHUFFLE_DecryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out);

/* AES-NI method — returns 0 on success, -1 if unavailable */
int  AES_NI_EncryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out);
int  AES_NI_DecryptBlock(const AES_Key *ctx, const uint8_t *in, uint8_t *out);

/* ─── Working modes ─── */

/*
 * CTR (Counter) mode.
 * Encrypts/decrypts len bytes of data in-place.
 * iv: 16-byte initial counter value (modified in-place as the counter advances).
 */
void AES_CTR_Encrypt(const AES_Key *ctx, const uint8_t *in, uint8_t *out,
                     uint32_t len, uint8_t *iv,
                     aes_encrypt_block_fn enc_fn);

/*
 * GCM (Galois/Counter Mode) — Authenticated Encryption.
 *
 * Encrypt: out = ciphertext, tag = 16-byte authentication tag.
 * Decrypt: out = plaintext, tag is verified (returns 0 on match, -1 on mismatch).
 *
 * iv: 12 bytes recommended (96-bit).  Other lengths are supported per NIST SP 800-38D.
 * aad: additional authenticated data (may be NULL if aad_len == 0).
 */
int  AES_GCM_Encrypt(const AES_Key *ctx, const uint8_t *in, uint8_t *out,
                     uint32_t len, const uint8_t *iv, uint32_t iv_len,
                     const uint8_t *aad, uint32_t aad_len,
                     uint8_t *tag, uint32_t tag_len,
                     aes_encrypt_block_fn enc_fn);
int  AES_GCM_Decrypt(const AES_Key *ctx, const uint8_t *in, uint8_t *out,
                     uint32_t len, const uint8_t *iv, uint32_t iv_len,
                     const uint8_t *aad, uint32_t aad_len,
                     const uint8_t *tag, uint32_t tag_len,
                     aes_encrypt_block_fn enc_fn);

/*
 * XTS (XEX-based tweaked-codebook mode with ciphertext stealing).
 * IEEE Std 1619-2007 for disk encryption.
 *
 * key_enc, key_dec: encryption/decryption keys (may be the same for AES).
 * tweak: 16-byte tweak (sector number).
 * len: data length in bytes, must be >= 16.
 */
void AES_XTS_Encrypt(const AES_Key *key_data, const AES_Key *key_tweak,
                     const uint8_t *in, uint8_t *out, uint32_t len,
                     const uint8_t *tweak, aes_encrypt_block_fn enc_fn);
void AES_XTS_Decrypt(const AES_Key *key_data, const AES_Key *key_tweak,
                     const uint8_t *in, uint8_t *out, uint32_t len,
                     const uint8_t *tweak,
                     aes_encrypt_block_fn enc_fn, aes_decrypt_block_fn dec_fn);

/* ─── Utility ─── */

/* Feature detection */
int  AES_HasAESNI(void);     /* returns 1 if AES-NI is available */
int  AES_HasSSSE3(void);     /* returns 1 if SSSE3 is available */

/* Get implementation name */
const char *AES_MethodName(int method);
#define AES_METHOD_SBOX    0
#define AES_METHOD_TBOX    1
#define AES_METHOD_SHUFFLE 2
#define AES_METHOD_NI      3

#ifdef __cplusplus
}
#endif

#endif /* AES_H */
