/*
 * AES Experiment — Internal helpers and constants
 */

#ifndef AES_INTERNAL_H
#define AES_INTERNAL_H

#include "aes.h"
#include <string.h>

/* ─── Byte-order helpers ─── */
static inline uint32_t LOAD_U32_BE(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) | ((uint32_t)p[3]);
}

static inline void STORE_U32_BE(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
}

static inline uint32_t ROTL32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

/* ─── AES S-box ─── */
extern const uint8_t AES_SBOX[256];
extern const uint8_t AES_INV_SBOX[256];

/* ─── Round constants ─── */
extern const uint32_t AES_RCON[10];

/* ─── Forward S-box substitution on a 32-bit word ─── */
#define AES_SUB_WORD(t) \
    ((AES_SBOX[((t) >> 24)] << 24) | \
     (AES_SBOX[((t) >> 16) & 0xFF] << 16) | \
     (AES_SBOX[((t) >>  8) & 0xFF] <<  8) | \
     (AES_SBOX[ (t)        & 0xFF]))

#define AES_INVSUB_WORD(t) \
    ((AES_INV_SBOX[((t) >> 24)] << 24) | \
     (AES_INV_SBOX[((t) >> 16) & 0xFF] << 16) | \
     (AES_INV_SBOX[((t) >>  8) & 0xFF] <<  8) | \
     (AES_INV_SBOX[ (t)        & 0xFF]))

/* ─── T-table declarations ─── */
extern const uint32_t AES_TE0[256];
extern const uint32_t AES_TE1[256];
extern const uint32_t AES_TE2[256];
extern const uint32_t AES_TE3[256];
extern const uint32_t AES_TD0[256];
extern const uint32_t AES_TD1[256];
extern const uint32_t AES_TD2[256];
extern const uint32_t AES_TD3[256];

/* ─── Cleanse ─── */
static inline void aes_cleanse(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}

#endif /* AES_INTERNAL_H */
