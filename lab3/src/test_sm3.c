/*
 * test_sm3.c - SM3 test program
 *
 * Tests correctness against GM/T 0004-2012 test vectors and
 * measures performance of baseline vs SIMD implementations.
 */

#define _POSIX_C_SOURCE 199309L

#include "sm3.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Test vector from GM/T 0004-2012: SM3("abc") */
static const char *test1_msg = "abc";
static const size_t test1_len = 3;
static const uint8_t test1_hash[32] = {
    0x66, 0xC7, 0xF0, 0xF4, 0x62, 0xEE, 0xED, 0xD9,
    0xD1, 0xF2, 0xD4, 0x6B, 0xDC, 0x10, 0xE4, 0xE2,
    0x41, 0x67, 0xC4, 0x87, 0x5C, 0xF2, 0xF7, 0xA2,
    0x29, 0x7D, 0xA0, 0x2B, 0x8F, 0x4B, 0xA8, 0xE0
};

/* Test vector from GM/T 0004-2012: SM3(64 x "abcd") */
static const char *test2_msg =
    "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
static const size_t test2_len = 64;
static const uint8_t test2_hash[32] = {
    0xDE, 0xBE, 0x9F, 0xF9, 0x22, 0x75, 0xB8, 0xA1,
    0x38, 0x60, 0x48, 0x89, 0xC1, 0x8E, 0x5A, 0x4D,
    0x6F, 0xDB, 0x70, 0xE5, 0x38, 0x7E, 0x57, 0x65,
    0x29, 0x3D, 0xCB, 0xA3, 0x9C, 0x0C, 0x57, 0x32
};

/* Empty string */
static const uint8_t test3_hash[32] = {
    0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F,
    0x8E, 0x61, 0x19, 0x48, 0x31, 0xE8, 0x1A, 0x8F,
    0x22, 0xBE, 0xC8, 0xC7, 0x28, 0xFE, 0xFB, 0x74,
    0x7E, 0xD0, 0x35, 0xEB, 0x50, 0x82, 0xAA, 0x2B
};

/*
 * HMAC-SM3 test vectors from gmcrypto / gmssl v3.1.1:
 *
 * Test 1: Key = 20 bytes of 0x0b, Msg = "Hi There"
 *   Expected: 51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70
 *
 * Test 2: Key = "Jefe", Msg = "what do ya want for nothing?"
 *   Expected: 2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882
 */
static const uint8_t hmac1_key[20] = {
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
};
static const char *hmac1_msg = "Hi There";
static const size_t hmac1_msg_len = 8;
static const uint8_t hmac1_expected[32] = {
    0x51,0xb0,0x0d,0x1f,0xb4,0x98,0x32,0xbf,
    0xb0,0x1c,0x3c,0xe2,0x78,0x48,0xe5,0x9f,
    0x87,0x1d,0x9b,0xa9,0x38,0xdc,0x56,0x3b,
    0x33,0x8c,0xa9,0x64,0x75,0x5c,0xce,0x70
};

static const char *hmac2_key = "Jefe";
static const size_t hmac2_key_len = 4;
static const char *hmac2_msg = "what do ya want for nothing?";
static const size_t hmac2_msg_len = 28;
static const uint8_t hmac2_expected[32] = {
    0x2e,0x87,0xf1,0xd1,0x68,0x62,0xe6,0xd9,
    0x64,0xb5,0x0a,0x52,0x00,0xbf,0x2b,0x10,
    0xb7,0x64,0xfa,0xa9,0x68,0x0a,0x29,0x6a,
    0x24,0x05,0xf2,0x4b,0xec,0x39,0xf8,0x82
};

static int tests_passed = 0;
static int tests_failed = 0;

static void hex_dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 4 == 0 && i + 1 < len) printf(" ");
    }
}

static int check_hash(const char *test_name,
                      const uint8_t *expected, const uint8_t *got)
{
    if (memcmp(expected, got, 32) == 0) {
        printf("  [PASS] %s\n", test_name);
        tests_passed++;
        return 1;
    } else {
        printf("  [FAIL] %s\n", test_name);
        printf("    Expected: ");
        hex_dump(expected, 32);
        printf("\n    Got:      ");
        hex_dump(got, 32);
        printf("\n");
        tests_failed++;
        return 0;
    }
}

static void test_sm3_basic(void)
{
    uint8_t digest[32];

    printf("--- SM3 Hash Tests ---\n");

    /* Test 1: "abc" */
    sm3_hash((const uint8_t *)test1_msg, test1_len, digest);
    check_hash("SM3(\"abc\")", test1_hash, digest);

    /* Test 2: 64 bytes of "abcd..." */
    sm3_hash((const uint8_t *)test2_msg, test2_len, digest);
    check_hash("SM3(64x\"abcd\")", test2_hash, digest);

    /* Test 3: empty string */
    sm3_hash((const uint8_t *)"", 0, digest);
    check_hash("SM3(\"\")", test3_hash, digest);

    /* Test 4: streaming API vs all-in-one */
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, (const uint8_t *)test1_msg, 1);
    sm3_update(&ctx, (const uint8_t *)test1_msg + 1, 1);
    sm3_update(&ctx, (const uint8_t *)test1_msg + 2, 1);
    sm3_final(&ctx, digest);
    check_hash("SM3 streaming \"abc\"", test1_hash, digest);
}

static void test_sm3_hmac(void)
{
    uint8_t mac[32];

    printf("--- HMAC-SM3 Tests ---\n");

    /* Test 1: Key=20×0x0b, Msg="Hi There" */
    sm3_hmac(hmac1_key, sizeof(hmac1_key),
             (const uint8_t *)hmac1_msg, hmac1_msg_len, mac);
    check_hash("HMAC-SM3 test 1 (0x0b key, \"Hi There\")", hmac1_expected, mac);

    /* Test 2: Key="Jefe", Msg="what do ya want for nothing?" */
    sm3_hmac((const uint8_t *)hmac2_key, hmac2_key_len,
             (const uint8_t *)hmac2_msg, hmac2_msg_len, mac);
    check_hash("HMAC-SM3 test 2 (\"Jefe\" key)", hmac2_expected, mac);
}

static void test_cross_implementation(void)
{
#if defined(SM3_HAS_SIMD) && (defined(__x86_64__) || defined(_M_X64))
    uint8_t digest_baseline[32], digest_avx2[32];

    printf("--- Cross-Implementation Verification ---\n");

    /* Compare baseline vs AVX2 */
    sm3_ctx_t ctx;

    sm3_init(&ctx);
    /* explicitly use baseline */
    sm3_compress(ctx.state, (const uint8_t *)test2_msg, 1);
    memcpy(digest_baseline, ctx.state, 32);

    sm3_init(&ctx);
    sm3_compress_avx2(ctx.state, (const uint8_t *)test2_msg, 1);
    memcpy(digest_avx2, ctx.state, 32);

    check_hash("Baseline C == AVX2 SIMD", digest_baseline, digest_avx2);
#elif defined(SM3_HAS_SIMD) && (defined(__aarch64__) || defined(__ARM_NEON))
    uint8_t digest_baseline[32], digest_neon[32];

    printf("--- Cross-Implementation Verification ---\n");

    sm3_ctx_t ctx;

    sm3_init(&ctx);
    sm3_compress(ctx.state, (const uint8_t *)test2_msg, 1);
    memcpy(digest_baseline, ctx.state, 32);

    sm3_init(&ctx);
    sm3_compress_neon(ctx.state, (const uint8_t *)test2_msg, 1);
    memcpy(digest_neon, ctx.state, 32);

    check_hash("Baseline C == NEON SIMD", digest_baseline, digest_neon);
#else
    (void)test2_msg; /* used */
    printf("--- Cross-Implementation Verification ---\n");
    printf("  [SKIP] SIMD variant not compiled in this build target.\n");
#endif
}

static double get_time_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void test_performance(void)
{
    printf("--- Performance Test (1 MB data) ---\n");

    const size_t size = 1024 * 1024;
    uint8_t *data = malloc(size);
    if (!data) {
        printf("  [SKIP] Cannot allocate memory\n");
        return;
    }

    /* Fill with pseudo-random data */
    for (size_t i = 0; i < size; i++) {
        data[i] = (uint8_t)(i * 31 + 17);
    }

    int iterations = 10;
    double best_baseline = 1e9;

    printf("  Baseline C... ");
    fflush(stdout);
    for (int n = 0; n < iterations; n++) {
        uint8_t digest[32];
        double start = get_time_sec();
        sm3_hash(data, size, digest);
        double elapsed = get_time_sec() - start;
        if (elapsed < best_baseline) best_baseline = elapsed;
    }
    printf("%.3f ms (best/%d)\n", best_baseline * 1000.0, iterations);

#if defined(__x86_64__) || defined(_M_X64)
    /* Build and run AVX2 version */
    double best_avx2 = 1e9;
    printf("  AVX2 SIMD... ");
    fflush(stdout);
    for (int n = 0; n < iterations; n++) {
        uint8_t digest[32];
        sm3_ctx_t ctx;
        double start = get_time_sec();
        sm3_init(&ctx);
        sm3_update(&ctx, data, size);
        sm3_final(&ctx, digest);
        double elapsed = get_time_sec() - start;
        if (elapsed < best_avx2) best_avx2 = elapsed;
    }
    printf("%.3f ms (best/%d)\n", best_avx2 * 1000.0, iterations);

    if (best_baseline > 0) {
        printf("  Speedup: %.2fx\n", best_baseline / best_avx2);
    }
#endif

    free(data);
}

int main(void)
{
    printf("SM3 Implementation Test Suite\n");
    printf("=============================\n");
    printf("Platform: ");
#if defined(__x86_64__) || defined(_M_X64)
    printf("x86_64 (AVX2 enabled)\n");
#elif defined(__aarch64__)
    printf("aarch64 (NEON enabled)\n");
#elif defined(__ARM_NEON)
    printf("ARM (NEON enabled)\n");
#else
    printf("Generic (baseline C)\n");
#endif

    test_sm3_basic();
    test_sm3_hmac();
    test_cross_implementation();
    test_performance();

    printf("\n=============================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
