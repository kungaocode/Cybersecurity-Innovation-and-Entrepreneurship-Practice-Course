/*
 * sm3.h - SM3 Cryptographic Hash Algorithm (GM/T 0004-2012)
 *
 * Standalone implementation adapted from openHiTLS (Mulan PSL v2).
 * Provides baseline C, AVX2 (x86_64), and ARM NEON (aarch64) versions.
 *
 * This is Experiment 2: SM3 Optimization
 * Phase 1: Pure C baseline
 * Phase 2: AVX2 SIMD + ARM NEON SIMD message expansion
 */

#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM3_BLOCK_SIZE      64
#define SM3_DIGEST_SIZE     32
#define SM3_HMAC_SIZE       32

/* SM3 context */
typedef struct {
    uint32_t state[8];          /* hash state (A,B,C,D,E,F,G,H) */
    uint8_t  block[SM3_BLOCK_SIZE]; /* pending data block */
    uint32_t num;               /* bytes in pending block */
    uint32_t lNum;              /* low 32 bits of bit count */
    uint32_t hNum;              /* high 32 bits of bit count */
} sm3_ctx_t;

/* Initialize context */
void sm3_init(sm3_ctx_t *ctx);

/* Feed data into the hash */
void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len);

/* Finalize and output 32-byte digest */
void sm3_final(sm3_ctx_t *ctx, uint8_t digest[SM3_DIGEST_SIZE]);

/* All-in-one: hash a message, returns 32-byte digest */
void sm3_hash(const uint8_t *msg, size_t len, uint8_t digest[SM3_DIGEST_SIZE]);

/* HMAC-SM3 (keyed hash) */
void sm3_hmac(const uint8_t *key, size_t key_len,
              const uint8_t *msg, size_t msg_len,
              uint8_t mac[SM3_HMAC_SIZE]);

/* Internal compression function (the core 64-round transform).
 * `blockCnt` = number of 64-byte blocks in `data`.
 * State is updated in place. */
void sm3_compress(uint32_t state[8], const uint8_t *data, size_t blockCnt);

/* AVX2-optimized compression (x86_64 only) */
#if defined(__x86_64__) || defined(_M_X64)
void sm3_compress_avx2(uint32_t state[8], const uint8_t *data, size_t blockCnt);
#endif

/* NEON-optimized compression (aarch64 only) */
#if defined(__aarch64__) || defined(__ARM_NEON)
void sm3_compress_neon(uint32_t state[8], const uint8_t *data, size_t blockCnt);
#endif

#ifdef __cplusplus
}
#endif

#endif /* SM3_H */
