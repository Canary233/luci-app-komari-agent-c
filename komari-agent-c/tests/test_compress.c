/*
 * test_compress.c - gzip compression/decompression unit tests
 *
 * Test scope:
 *   - compress_gzip / compress_gunzip round-trip on various inputs
 *   - Empty input handling
 *   - NULL argument rejection
 *   - Decompression of corrupt input must fail (not loop forever)
 *   - gzip bomb protection: decompressed output above MAX_DECOMPRESSED_SIZE
 *     (16 MB) must be rejected
 *
 * Note: These tests exercise the real zlib-backed implementation and allocate
 * real memory; they run on any platform with zlib installed.
 */

#include "unity.h"
#include "compress.h"

#include <stdlib.h>
#include <string.h>

void setUp(void) {
}

void tearDown(void) {
}

/* ====== compress_gzip / compress_gunzip round-trip ====== */

/* Round-trip a simple ASCII string. */
void test_compress_roundtrip_simple(void) {
    const char *input = "Hello, gzip world!";
    size_t input_len = strlen(input);

    char *compressed = NULL;
    size_t compressed_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_gzip(input, input_len, &compressed, &compressed_len));
    TEST_ASSERT_NOT_NULL(compressed);
    TEST_ASSERT_TRUE(compressed_len > 0);

    char *decompressed = NULL;
    size_t decompressed_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_gunzip(compressed, compressed_len,
                                              &decompressed, &decompressed_len));
    TEST_ASSERT_NOT_NULL(decompressed);
    TEST_ASSERT_EQUAL_size_t(input_len, decompressed_len);
    TEST_ASSERT_EQUAL_MEMORY(input, decompressed, input_len);

    free(compressed);
    free(decompressed);
}

/* Round-trip a larger input that spans multiple deflate chunks. */
void test_compress_roundtrip_large_input(void) {
    /* 100 KB of repeating data — large enough to exercise the buffer-growth
     * path in compress_gzip (initial 4 KB buffer will need to expand). */
    size_t input_len = 100 * 1024;
    char *input = (char *)malloc(input_len);
    TEST_ASSERT_NOT_NULL(input);
    for (size_t i = 0; i < input_len; i++) {
        input[i] = (char)('A' + (i % 26));
    }

    char *compressed = NULL;
    size_t compressed_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_gzip(input, input_len, &compressed, &compressed_len));
    TEST_ASSERT_NOT_NULL(compressed);

    char *decompressed = NULL;
    size_t decompressed_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_gunzip(compressed, compressed_len,
                                              &decompressed, &decompressed_len));
    TEST_ASSERT_EQUAL_size_t(input_len, decompressed_len);
    TEST_ASSERT_EQUAL_MEMORY(input, decompressed, input_len);

    free(input);
    free(compressed);
    free(decompressed);
}

/* Empty input compresses to a valid gzip stream and decompresses back to empty. */
void test_compress_roundtrip_empty_input(void) {
    const char *input = "";
    size_t input_len = 0;

    char *compressed = NULL;
    size_t compressed_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_gzip(input, input_len, &compressed, &compressed_len));
    TEST_ASSERT_NOT_NULL(compressed);
    /* A gzip stream of empty input still has the header + trailer (>= 18 bytes). */
    TEST_ASSERT_TRUE(compressed_len >= 18);

    char *decompressed = NULL;
    size_t decompressed_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_gunzip(compressed, compressed_len,
                                              &decompressed, &decompressed_len));
    TEST_ASSERT_EQUAL_size_t(0, decompressed_len);

    free(compressed);
    free(decompressed);
}

/* ====== NULL argument rejection ====== */

void test_compress_gzip_null_args(void) {
    const char *input = "x";
    char *out = NULL;
    size_t out_len = 0;

    TEST_ASSERT_EQUAL_INT(-1, compress_gzip(NULL, 1, &out, &out_len));
    TEST_ASSERT_EQUAL_INT(-1, compress_gzip(input, 1, NULL, &out_len));
    TEST_ASSERT_EQUAL_INT(-1, compress_gzip(input, 1, &out, NULL));
}

void test_compress_gunzip_null_args(void) {
    const char *input = "x";
    char *out = NULL;
    size_t out_len = 0;

    TEST_ASSERT_EQUAL_INT(-1, compress_gunzip(NULL, 1, &out, &out_len));
    TEST_ASSERT_EQUAL_INT(-1, compress_gunzip(input, 1, NULL, &out_len));
    TEST_ASSERT_EQUAL_INT(-1, compress_gunzip(input, 1, &out, NULL));
}

/* ====== Corrupt input handling ====== */

/* Decompressing random (non-gzip) bytes must fail, not loop forever. */
void test_compress_gunzip_corrupt_input(void) {
    /* 64 bytes of non-gzip garbage. The gzip header check should reject this
     * quickly; the key assertion is that the function returns at all (the
     * pre-fix code could infinite-loop on corrupt input). */
    char garbage[64];
    for (size_t i = 0; i < sizeof(garbage); i++) {
        garbage[i] = (char)(i * 7 + 13);
    }

    char *out = NULL;
    size_t out_len = 0;
    TEST_ASSERT_EQUAL_INT(-1, compress_gunzip(garbage, sizeof(garbage), &out, &out_len));
    TEST_ASSERT_NULL(out);
    TEST_ASSERT_EQUAL_size_t(0, out_len);
}

/* Decompressing a truncated gzip stream must fail. */
void test_compress_gunzip_truncated_input(void) {
    const char *input = " compressible input for truncation test ";
    size_t input_len = strlen(input);

    char *compressed = NULL;
    size_t compressed_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_gzip(input, input_len, &compressed, &compressed_len));

    /* Truncate the compressed stream to half its length (drop the trailer). */
    size_t truncated_len = compressed_len / 2;
    char *out = NULL;
    size_t out_len = 0;
    TEST_ASSERT_EQUAL_INT(-1, compress_gunzip(compressed, truncated_len, &out, &out_len));
    TEST_ASSERT_NULL(out);

    free(compressed);
}

/* ====== gzip bomb protection ====== */

/* A highly compressible 32 MB input compressed into a tiny gzip stream must
 * be rejected on decompression because the expanded output exceeds the
 * 16 MB MAX_DECOMPRESSED_SIZE guard. This verifies the bomb guard actually
 * fires rather than allocating unbounded memory. */
void test_compress_gunzip_rejects_bomb(void) {
    /* Build a 32 MB input of identical bytes — compresses to a few KB. */
    size_t bomb_len = 32 * 1024 * 1024;
    char *bomb = (char *)malloc(bomb_len);
    TEST_ASSERT_NOT_NULL(bomb);
    memset(bomb, 'X', bomb_len);

    char *compressed = NULL;
    size_t compressed_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_gzip(bomb, bomb_len, &compressed, &compressed_len));
    /* The compressed form must be much smaller than the original. */
    TEST_ASSERT_TRUE(compressed_len < bomb_len / 100);

    /* Decompression must refuse to expand past MAX_DECOMPRESSED_SIZE (16 MB). */
    char *out = NULL;
    size_t out_len = 0;
    TEST_ASSERT_EQUAL_INT(-1, compress_gunzip(compressed, compressed_len, &out, &out_len));
    TEST_ASSERT_NULL(out);
    TEST_ASSERT_EQUAL_size_t(0, out_len);

    free(bomb);
    free(compressed);
}

/* ====== compress_is_available ====== */

void test_compress_is_available_returns_one(void) {
    /* The implementation has a hard dependency on zlib, so this always returns 1.
     * The test documents the contract; a future build without zlib would need
     * to update both the implementation and this test. */
    TEST_ASSERT_EQUAL_INT(1, compress_is_available());
}

/* ====== raw DEFLATE streams (permessage-deflate support) ====== */

/* Round-trip: deflate produces the 00 00 FF FF sync-flush tail; stripping
 * it and re-appending via inflate(append_pmd_tail=1) restores the input. */
void test_compress_raw_roundtrip(void) {
    const char *input = "permessage-deflate payload with enough text to compress";
    size_t input_len = strlen(input);

    compress_raw_t defl;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_deflate_init(&defl));

    char *comp = NULL;
    size_t comp_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_deflate(&defl, input, input_len,
                                                  &comp, &comp_len));
    TEST_ASSERT_NOT_NULL(comp);
    TEST_ASSERT_TRUE(comp_len >= 4);
    TEST_ASSERT_EQUAL_UINT8(0x00, (unsigned char)comp[comp_len - 4]);
    TEST_ASSERT_EQUAL_UINT8(0x00, (unsigned char)comp[comp_len - 3]);
    TEST_ASSERT_EQUAL_UINT8(0xFF, (unsigned char)comp[comp_len - 2]);
    TEST_ASSERT_EQUAL_UINT8(0xFF, (unsigned char)comp[comp_len - 1]);
    compress_raw_deflate_end(&defl);

    compress_raw_t infl;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_inflate_init(&infl));
    char *plain = NULL;
    size_t plain_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_inflate(&infl, comp, comp_len - 4,
                                                  1, 0, &plain, &plain_len));
    TEST_ASSERT_NOT_NULL(plain);
    TEST_ASSERT_EQUAL_size_t(input_len, plain_len);
    TEST_ASSERT_EQUAL_MEMORY(input, plain, input_len);

    free(comp);
    free(plain);
    compress_raw_inflate_end(&infl);
}

/* Context takeover: two messages through the same context must inflate
 * correctly when fed through the same inflate context. */
void test_compress_raw_context_takeover(void) {
    const char *msg1 = "first message repeated data aaaa bbbb cccc dddd";
    const char *msg2 = "second message similar structure eeee ffff gggg";

    compress_raw_t defl;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_deflate_init(&defl));
    char *c1 = NULL, *c2 = NULL;
    size_t c1_len = 0, c2_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_deflate(&defl, msg1, strlen(msg1), &c1, &c1_len));
    TEST_ASSERT_EQUAL_INT(0, compress_raw_deflate(&defl, msg2, strlen(msg2), &c2, &c2_len));
    compress_raw_deflate_end(&defl);

    compress_raw_t infl;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_inflate_init(&infl));
    char *p1 = NULL, *p2 = NULL;
    size_t p1_len = 0, p2_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_inflate(&infl, c1, c1_len - 4, 1, 0,
                                                  &p1, &p1_len));
    TEST_ASSERT_EQUAL_INT(0, compress_raw_inflate(&infl, c2, c2_len - 4, 1, 0,
                                                  &p2, &p2_len));
    TEST_ASSERT_EQUAL_size_t(strlen(msg1), p1_len);
    TEST_ASSERT_EQUAL_MEMORY(msg1, p1, p1_len);
    TEST_ASSERT_EQUAL_size_t(strlen(msg2), p2_len);
    TEST_ASSERT_EQUAL_MEMORY(msg2, p2, p2_len);

    free(c1); free(c2); free(p1); free(p2);
    compress_raw_inflate_end(&infl);
}

/* An empty message deflates to zero stripped bytes and inflates back to
 * empty via the tail marker alone. */
void test_compress_raw_empty_message(void) {
    compress_raw_t defl;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_deflate_init(&defl));
    char *comp = NULL;
    size_t comp_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_deflate(&defl, "", 0, &comp, &comp_len));
    compress_raw_deflate_end(&defl);
    TEST_ASSERT_NOT_NULL(comp);

    compress_raw_t infl;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_inflate_init(&infl));
    char *plain = NULL;
    size_t plain_len = 0;
    /* comp may be empty (0 bytes) or carry only the sync marker; feeding
     * the marker-less remainder with append_pmd_tail=1 must yield nothing. */
    size_t wire_len = comp_len >= 4 ? comp_len - 4 : 0;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_inflate(&infl, comp, wire_len, 1, 0,
                                                  &plain, &plain_len));
    TEST_ASSERT_EQUAL_size_t(0, plain_len);
    free(comp);
    free(plain);
    compress_raw_inflate_end(&infl);
}

/* The per-call max_out cap on inflate must reject oversized expansions. */
void test_compress_raw_inflate_bomb_guard(void) {
    size_t bomb_len = 1024 * 1024;
    char *bomb = malloc(bomb_len);
    TEST_ASSERT_NOT_NULL(bomb);
    memset(bomb, 'X', bomb_len);

    compress_raw_t defl;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_deflate_init(&defl));
    char *comp = NULL;
    size_t comp_len = 0;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_deflate(&defl, bomb, bomb_len,
                                                  &comp, &comp_len));
    compress_raw_deflate_end(&defl);
    TEST_ASSERT_TRUE(comp_len < bomb_len);

    compress_raw_t infl;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_inflate_init(&infl));
    char *plain = NULL;
    size_t plain_len = 0;
    /* Cap far below the 1 MB expansion; inflate must fail, not allocate. */
    TEST_ASSERT_EQUAL_INT(-1, compress_raw_inflate(&infl, comp, comp_len - 4,
                                                   1, 4096, &plain, &plain_len));
    TEST_ASSERT_NULL(plain);
    free(comp);
    free(bomb);
    compress_raw_inflate_end(&infl);
}

void test_compress_raw_null_args(void) {
    compress_raw_t defl;
    TEST_ASSERT_EQUAL_INT(-1, compress_raw_deflate_init(NULL));
    TEST_ASSERT_EQUAL_INT(0, compress_raw_deflate_init(&defl));
    char *out = NULL;
    size_t out_len = 0;
    TEST_ASSERT_EQUAL_INT(-1, compress_raw_deflate(NULL, "x", 1, &out, &out_len));
    TEST_ASSERT_EQUAL_INT(-1, compress_raw_deflate(&defl, "x", 1, NULL, &out_len));
    compress_raw_deflate_end(&defl);

    compress_raw_t infl;
    TEST_ASSERT_EQUAL_INT(0, compress_raw_inflate_init(&infl));
    TEST_ASSERT_EQUAL_INT(-1, compress_raw_inflate(&infl, "x", 1, 0, 0, NULL, &out_len));
    TEST_ASSERT_EQUAL_INT(-1, compress_raw_inflate(NULL, "x", 1, 0, 0, &out, &out_len));
    compress_raw_inflate_end(&infl);

    TEST_ASSERT_EQUAL_INT(-1, compress_raw_inflate_init(NULL));
}

int main(void) {
    UNITY_BEGIN();

    /* Round-trip tests */
    RUN_TEST(test_compress_roundtrip_simple);
    RUN_TEST(test_compress_roundtrip_large_input);
    RUN_TEST(test_compress_roundtrip_empty_input);

    /* NULL argument rejection */
    RUN_TEST(test_compress_gzip_null_args);
    RUN_TEST(test_compress_gunzip_null_args);

    /* Corrupt input handling */
    RUN_TEST(test_compress_gunzip_corrupt_input);
    RUN_TEST(test_compress_gunzip_truncated_input);

    /* gzip bomb protection */
    RUN_TEST(test_compress_gunzip_rejects_bomb);

    /* Availability */
    RUN_TEST(test_compress_is_available_returns_one);

    /* Raw DEFLATE streams */
    RUN_TEST(test_compress_raw_roundtrip);
    RUN_TEST(test_compress_raw_context_takeover);
    RUN_TEST(test_compress_raw_empty_message);
    RUN_TEST(test_compress_raw_inflate_bomb_guard);
    RUN_TEST(test_compress_raw_null_args);

    return UNITY_END();
}
