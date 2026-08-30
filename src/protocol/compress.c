/*
 * gzip compression/decompression implementation using zlib.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#include "compress.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>

#include "logger.h"

/* Initial output buffer size */
#define COMPRESS_CHUNK_SIZE 4096

/* Per-call overhead added to input_len when sizing the initial compression
 * buffer (zlib header + trailer + small slack). */
#define COMPRESS_SIZE_OVERHEAD 128

/* Initial decompression expansion factor applied to input_len. */
#define DECOMPRESS_INITIAL_FACTOR 4

/* Maximum acceptable decompressed output size. Protects against gzip bombs
 * where a tiny compressed payload expands into an unbounded stream. */
#define MAX_DECOMPRESSED_SIZE (16 * 1024 * 1024)

int compress_gzip(const char *input, size_t input_len,
                   char **output, size_t *output_len)
{
    if (!input || !output || !output_len) {
        return -1;
    }

    *output = NULL;
    *output_len = 0;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    /* windowBits = 15 + 16 indicates gzip output format */
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                      15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }

    strm.next_in = (Bytef *)input;
    strm.avail_in = (uInt)input_len;

    /* Initial buffer: input size + header/trailer overhead, at least CHUNK_SIZE.
     * Guard against integer overflow on input_len + overhead (MIN-44/45):
     * if input_len is so large that adding the overhead would wrap around,
     * the requested buffer would be smaller than expected (or zero) and the
     * subsequent memcpy/deflate could write out of bounds. */
    if (input_len > SIZE_MAX - COMPRESS_SIZE_OVERHEAD) {
        KOMARI_LOG_ERROR("compress: input_len %zu overflows size_t", input_len);
        deflateEnd(&strm);
        return -1;
    }
    size_t buf_size = input_len + COMPRESS_SIZE_OVERHEAD;
    if (buf_size < COMPRESS_CHUNK_SIZE) {
        buf_size = COMPRESS_CHUNK_SIZE;
    }

    char *buf = (char *)malloc(buf_size);
    if (!buf) {
        deflateEnd(&strm);
        return -1;
    }

    strm.next_out = (Bytef *)buf;
    strm.avail_out = (uInt)buf_size;

    int ret;
    do {
        ret = deflate(&strm, Z_FINISH);

        if (ret == Z_OK || ret == Z_BUF_ERROR) {
            /* Output buffer insufficient; needs to be expanded.
             * Guard against size_t wrap when doubling (MIN-44/45). */
            size_t used = buf_size - strm.avail_out;
            if (buf_size > SIZE_MAX / 2) {
                KOMARI_LOG_ERROR("compress: output buffer size %zu overflows on growth", buf_size);
                free(buf);
                deflateEnd(&strm);
                return -1;
            }
            size_t new_size = buf_size * 2;
            char *new_buf = (char *)realloc(buf, new_size);
            if (!new_buf) {
                free(buf);
                deflateEnd(&strm);
                return -1;
            }
            buf = new_buf;
            buf_size = new_size;
            strm.next_out = (Bytef *)(buf + used);
            strm.avail_out = (uInt)(buf_size - used);
        }
    } while (ret == Z_OK || ret == Z_BUF_ERROR);

    if (ret != Z_STREAM_END) {
        free(buf);
        deflateEnd(&strm);
        return -1;
    }

    *output = buf;
    *output_len = buf_size - strm.avail_out;

    deflateEnd(&strm);
    return 0;
}

int compress_gunzip(const char *input, size_t input_len,
                     char **output, size_t *output_len)
{
    if (!input || !output || !output_len) {
        return -1;
    }

    *output = NULL;
    *output_len = 0;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    /* windowBits = 15 + 16 indicates the input is in gzip format */
    if (inflateInit2(&strm, 15 + 16) != Z_OK) {
        return -1;
    }

    strm.next_in = (Bytef *)input;
    strm.avail_in = (uInt)input_len;

    /* Initial buffer: 4x the input size, at least CHUNK_SIZE.
     * Guard against size_t overflow on the multiplication (MIN-44/45): if
     * input_len exceeds SIZE_MAX / 4 the product wraps to a small value and
     * inflate would write past the end of the undersized buffer. Cap the
     * initial size at MAX_DECOMPRESSED_SIZE so the bomb guard below stays
     * meaningful. */
    if (input_len > MAX_DECOMPRESSED_SIZE / DECOMPRESS_INITIAL_FACTOR) {
        KOMARI_LOG_ERROR("gunzip: input_len %zu exceeds decompression limit", input_len);
        inflateEnd(&strm);
        return -1;
    }
    size_t buf_size = input_len * DECOMPRESS_INITIAL_FACTOR;
    if (buf_size < COMPRESS_CHUNK_SIZE) {
        buf_size = COMPRESS_CHUNK_SIZE;
    }

    char *buf = (char *)malloc(buf_size);
    if (!buf) {
        inflateEnd(&strm);
        return -1;
    }

    size_t total_out = 0;
    int ret;

    do {
        /* Bomb guard: refuse to keep producing output beyond the cap. */
        if (total_out > MAX_DECOMPRESSED_SIZE) {
            KOMARI_LOG_WARN("gunzip: decompressed output exceeds %d bytes limit, aborting",
                            MAX_DECOMPRESSED_SIZE);
            free(buf);
            inflateEnd(&strm);
            return -1;
        }

        strm.next_out = (Bytef *)(buf + total_out);
        strm.avail_out = (uInt)(buf_size - total_out);

        ret = inflate(&strm, Z_NO_FLUSH);

        total_out = buf_size - strm.avail_out;

        if (ret == Z_STREAM_END) {
            /* Decompression finished successfully */
            break;
        }

        /* Z_DATA_ERROR, Z_MEM_ERROR, Z_NEED_DICT, etc. are fatal. The
         * original loop kept retrying inflate on these states, which
         * caused an infinite loop on truncated or corrupt gzip data. */
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            free(buf);
            inflateEnd(&strm);
            return -1;
        }

        /* Z_BUF_ERROR with a non-full output buffer means no progress is
         * possible (typically truncated input). Break to avoid looping
         * forever; the Z_STREAM_END check below reports the failure. */
        if (ret == Z_BUF_ERROR && strm.avail_out > 0) {
            break;
        }

        /* Output buffer is full; expand it (subject to the bomb guard). */
        if (strm.avail_out == 0) {
            if (buf_size >= MAX_DECOMPRESSED_SIZE) {
                KOMARI_LOG_WARN("gunzip: decompressed output exceeds %d bytes limit, aborting",
                                MAX_DECOMPRESSED_SIZE);
                free(buf);
                inflateEnd(&strm);
                return -1;
            }

            size_t new_size = buf_size * 2;
            if (new_size > MAX_DECOMPRESSED_SIZE) {
                new_size = MAX_DECOMPRESSED_SIZE;
            }
            char *new_buf = (char *)realloc(buf, new_size);
            if (!new_buf) {
                free(buf);
                inflateEnd(&strm);
                return -1;
            }
            buf = new_buf;
            buf_size = new_size;
        }
    } while (1);

    if (ret != Z_STREAM_END) {
        free(buf);
        inflateEnd(&strm);
        return -1;
    }

    *output = buf;
    *output_len = total_out;

    inflateEnd(&strm);
    return 0;
}

int compress_is_available(void)
{
    /* The current implementation has a hard dependency on zlib; always available */
    return 1;
}

/* ------------------------------------------------------------------ */
/* Raw DEFLATE streams (RFC 7692 permessage-deflate support)           */
/* ------------------------------------------------------------------ */

/* Sync-flush marker produced by deflate(Z_SYNC_FLUSH) and expected after
 * every permessage-deflate payload. */
static const unsigned char PMD_TAIL[4] = {0x00, 0x00, 0xFF, 0xFF};

int compress_raw_deflate_init(compress_raw_t *ctx)
{
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));
    if (deflateInit2(&ctx->strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }
    ctx->initialized = 1;
    return 0;
}

int compress_raw_deflate(compress_raw_t *ctx, const char *input,
                         size_t input_len, char **output, size_t *output_len)
{
    if (!ctx || !ctx->initialized || !output || !output_len) return -1;

    *output = NULL;
    *output_len = 0;

    size_t buf_size = input_len + input_len / 2 + 64;
    char *buf = malloc(buf_size);
    if (!buf) return -1;

    ctx->strm.next_in = (Bytef *)(uintptr_t)input;
    ctx->strm.avail_in = (uInt)input_len;
    ctx->strm.next_out = (Bytef *)buf;
    ctx->strm.avail_out = (uInt)buf_size;

    int ret;
    for (;;) {
        ret = deflate(&ctx->strm, Z_SYNC_FLUSH);
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            free(buf);
            return -1;
        }
        if (ctx->strm.avail_out == 0) {
            /* Grow while zlib cannot fit pending output. */
            size_t used = buf_size;
            size_t new_size = buf_size * 2;
            char *nb = realloc(buf, new_size);
            if (!nb) {
                free(buf);
                return -1;
            }
            buf = nb;
            buf_size = new_size;
            ctx->strm.next_out = (Bytef *)(buf + used);
            ctx->strm.avail_out = (uInt)(new_size - used);
            continue;
        }
        /* Done when all input is consumed and the flush completed. An empty
         * input yields Z_BUF_ERROR with zero output, which is valid for
         * permessage-deflate (the peer inflates the tail marker alone). */
        if (ctx->strm.avail_in == 0) break;
    }

    *output = buf;
    *output_len = buf_size - ctx->strm.avail_out;
    return 0;
}

void compress_raw_deflate_end(compress_raw_t *ctx)
{
    if (!ctx || !ctx->initialized) return;
    deflateEnd(&ctx->strm);
    ctx->initialized = 0;
}

int compress_raw_inflate_init(compress_raw_t *ctx)
{
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));
    if (inflateInit2(&ctx->strm, -15) != Z_OK) {
        return -1;
    }
    ctx->initialized = 1;
    return 0;
}

/* Feed one input region into inflate, growing the output buffer. */
static int raw_inflate_feed(compress_raw_t *ctx, char **buf, size_t *buf_size,
                            size_t *total_out, size_t max_out,
                            const unsigned char *in, size_t in_len)
{
    ctx->strm.next_in = (Bytef *)(uintptr_t)in;
    ctx->strm.avail_in = (uInt)in_len;
    while (ctx->strm.avail_in > 0) {
        if (*total_out >= max_out) return -1;
        ctx->strm.next_out = (Bytef *)(*buf + *total_out);
        ctx->strm.avail_out = (uInt)(*buf_size - *total_out);
        int ret = inflate(&ctx->strm, Z_NO_FLUSH);
        *total_out = *buf_size - ctx->strm.avail_out;
        if (ret == Z_STREAM_END) {
            /* A raw stream should not end mid-conversation; treat it as
             * corrupt input for our usage. */
            return -1;
        }
        if (ret != Z_OK) return -1;
        if (ctx->strm.avail_out == 0) {
            size_t new_size = *buf_size * 2;
            if (new_size > max_out) new_size = max_out;
            if (new_size <= *buf_size) return -1; /* Cap reached. */
            char *nb = realloc(*buf, new_size);
            if (!nb) return -1;
            *buf = nb;
            *buf_size = new_size;
        }
    }
    return 0;
}

int compress_raw_inflate(compress_raw_t *ctx, const char *input,
                         size_t input_len, int append_pmd_tail,
                         size_t max_out, char **output, size_t *output_len)
{
    if (!ctx || !ctx->initialized || !output || !output_len) return -1;
    if (max_out == 0) max_out = MAX_DECOMPRESSED_SIZE;

    *output = NULL;
    *output_len = 0;

    size_t buf_size = (input_len + 1) * 4;
    if (buf_size < 1024) buf_size = 1024;
    if (buf_size > max_out) buf_size = max_out;
    char *buf = malloc(buf_size);
    if (!buf) return -1;

    size_t total_out = 0;
    if (input_len > 0 &&
        raw_inflate_feed(ctx, &buf, &buf_size, &total_out, max_out,
                         (const unsigned char *)input, input_len) != 0) {
        free(buf);
        return -1;
    }
    if (append_pmd_tail &&
        raw_inflate_feed(ctx, &buf, &buf_size, &total_out, max_out,
                         PMD_TAIL, sizeof(PMD_TAIL)) != 0) {
        free(buf);
        return -1;
    }

    *output = buf;
    *output_len = total_out;
    return 0;
}

void compress_raw_inflate_end(compress_raw_t *ctx)
{
    if (!ctx || !ctx->initialized) return;
    inflateEnd(&ctx->strm);
    ctx->initialized = 0;
}
