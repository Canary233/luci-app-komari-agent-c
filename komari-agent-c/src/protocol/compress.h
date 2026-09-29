/*
 * gzip compression/decompression helpers backed by zlib.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#ifndef KOMARI_AGENT_C_COMPRESS_H
#define KOMARI_AGENT_C_COMPRESS_H

#include <stddef.h>
#include <zlib.h>

/**
 * gzip compression.
 *
 * @param input      Data to compress.
 * @param input_len  Length of the data to compress (in bytes).
 * @param output     Outputs a pointer to the output buffer, which is allocated
 *                   internally. The caller must free it.
 * @param output_len Outputs the length of the output data (in bytes).
 * @return 0 on success, -1 on failure.
 */
int compress_gzip(const char *input, size_t input_len,
                   char **output, size_t *output_len);

/**
 * gzip decompression.
 *
 * @param input      Data to decompress.
 * @param input_len  Length of the data to decompress (in bytes).
 * @param output     Outputs a pointer to the output buffer, which is allocated
 *                   internally. The caller must free it.
 * @param output_len Outputs the length of the output data (in bytes).
 * @return 0 on success, -1 on failure.
 */
int compress_gunzip(const char *input, size_t input_len,
                     char **output, size_t *output_len);

/**
 * Check whether zlib is available.
 *
 * @return Always returns 1 (the current implementation has a hard dependency on zlib).
 */
int compress_is_available(void);

/**
 * Streaming raw-DEFLATE context for RFC 7692 (permessage-deflate).
 * The z_stream is kept across calls so the sliding window carries over
 * between messages (context takeover), as required by the WebSocket
 * extension. Not thread-safe: each WebSocket connection owns its pair.
 */
typedef struct {
    z_stream strm;
    int initialized;
} compress_raw_t;

/**
 * Initialize a raw-DEFLATE (windowBits -15) compression context.
 *
 * @param ctx Context to initialize
 * @return 0 on success, -1 on failure
 */
int compress_raw_deflate_init(compress_raw_t *ctx);

/**
 * Reset a raw-DEFLATE compression context so the next message starts with
 * an empty sliding window. Used when the peer negotiates
 * client_no_context_takeover (RFC 7692 §7.1.1.1).
 *
 * @param ctx Context from compress_raw_deflate_init
 * @return 0 on success, -1 on failure
 */
int compress_raw_deflate_reset(compress_raw_t *ctx);

/**
 * Compress one message with Z_SYNC_FLUSH. The produced output ends with
 * the 00 00 FF FF sync-flush marker, which per RFC 7692 must be stripped
 * before the payload is sent on the wire; this function does NOT strip it
 * so it can also be used for generic raw-deflate framing.
 *
 * @param ctx       Context from compress_raw_deflate_init
 * @param input     Message data (may be NULL/0-length)
 * @param input_len Message length
 * @param output    Outputs a heap buffer the caller must free
 * @param output_len Outputs the compressed length
 * @return 0 on success, -1 on failure
 */
int compress_raw_deflate(compress_raw_t *ctx, const char *input,
                         size_t input_len, char **output, size_t *output_len);

/**
 * Release a raw-DEFLATE compression context.
 */
void compress_raw_deflate_end(compress_raw_t *ctx);

/**
 * Initialize a raw-DEFLATE (windowBits -15) decompression context.
 *
 * @param ctx Context to initialize
 * @return 0 on success, -1 on failure
 */
int compress_raw_inflate_init(compress_raw_t *ctx);

/**
 * Reset a raw-DEFLATE decompression context so the next message starts with
 * an empty sliding window. Used when the peer negotiates
 * server_no_context_takeover (RFC 7692 §7.1.1.1).
 *
 * @param ctx Context from compress_raw_inflate_init
 * @return 0 on success, -1 on failure
 */
int compress_raw_inflate_reset(compress_raw_t *ctx);

/**
 * Decompress one message chunk group. The output grows until all input is
 * consumed; a per-call output cap protects against decompression bombs.
 *
 * @param ctx            Context from compress_raw_inflate_init
 * @param input          Compressed data
 * @param input_len      Length of the compressed data
 * @param append_pmd_tail Append the 00 00 FF FF tail required by RFC 7692
 *                         (peer strips it before sending)
 * @param max_out        Hard cap on decompressed size (0 => 16 MiB)
 * @param output         Outputs a heap buffer the caller must free
 * @param output_len     Outputs the decompressed length
 * @return 0 on success, -1 on failure (corrupt data, cap exceeded)
 */
int compress_raw_inflate(compress_raw_t *ctx, const char *input,
                         size_t input_len, int append_pmd_tail,
                         size_t max_out, char **output, size_t *output_len);

/**
 * Release a raw-DEFLATE decompression context.
 */
void compress_raw_inflate_end(compress_raw_t *ctx);

#endif /* KOMARI_AGENT_C_COMPRESS_H */
