/*
 * Minimal blocking HTTP/1.1 client over plain TCP or TLS (OpenSSL).
 *
 * Single-shot requests with Connection: close semantics. Supports
 * in-memory or streaming request bodies, in-memory or streaming response
 * bodies, Content-Length and chunked transfer decoding, and optional gzip
 * request compression. Mirrors the Go reference implementation's behavior
 * of POSTing JSON-RPC payloads with optional Content-Encoding: gzip.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#ifndef KOMARI_AGENT_C_HTTP_CLIENT_H
#define KOMARI_AGENT_C_HTTP_CLIENT_H

#include <stddef.h>
#include <sys/types.h>

/* Default cap for internally buffered response bodies. */
#define HTTP_CLIENT_DEFAULT_MAX_RESPONSE (4u * 1024u * 1024u)

/* Default connect and I/O timeout (seconds). */
#define HTTP_CLIENT_DEFAULT_TIMEOUT_SEC 30

/**
 * Streaming request body provider. Called repeatedly to fill the output
 * buffer until it returns 0 (end of body) or -1 (error, aborts request).
 *
 * @param user Opaque user context from http_client_request_t::body_user
 * @param buf  Destination buffer
 * @param len  Buffer capacity
 * @return Number of bytes produced (>= 0), 0 on end of body, -1 on error
 */
typedef ssize_t (*http_client_body_reader_t)(void *user, char *buf, size_t len);

/**
 * Streaming response body sink. Called for each decoded chunk of the
 * response body. Used for large transfers that must not be buffered in
 * memory (e.g. file-manager upload/download streams).
 *
 * @param user Opaque user context from http_client_request_t::writer_user
 * @param data Decoded body chunk (not NUL-terminated)
 * @param len  Chunk length in bytes
 * @return 0 to continue, -1 to abort the transfer
 */
typedef int (*http_client_body_writer_t)(void *user, const char *data, size_t len);

/**
 * Request description. Zero the whole struct, then fill the fields.
 * Only url is mandatory; everything else has a sensible default.
 */
typedef struct {
    const char *url;            /* Required. http:// or https:// URL. */
    const char *method;         /* NULL => "POST". */
    const char *content_type;   /* NULL => "application/json". */
    const char *extra_headers;  /* Pre-formatted "Key: value\r\n" lines, or NULL. */

    /* Request body: use either (body, body_len) or (body_reader, body_user).
     * When body is non-NULL with body_len == 0, strlen(body) is used. */
    const char *body;
    size_t body_len;
    http_client_body_reader_t body_reader; /* Streaming provider (optional). */
    void *body_user;

    /* Response handling: use at most one of the three modes.
     * 1. response_buf/response_len: capture into a caller-owned fixed buffer.
     * 2. body_writer/writer_user: stream decoded chunks to a sink.
     * 3. neither: response.body is heap-allocated (caller frees via
     *    http_client_response_free), capped at max_response bytes. */
    char *response_buf;
    size_t response_len;
    http_client_body_writer_t body_writer;
    void *writer_user;
    size_t max_response;        /* Mode 3 only; 0 => HTTP_CLIENT_DEFAULT_MAX_RESPONSE. */

    /* Connection options. */
    int ignore_cert;            /* Skip TLS certificate verification. */
    int timeout_sec;            /* Connect + I/O timeout; 0 => default 30. */
    int gzip_body;              /* Gzip the in-memory body and set Content-Encoding. */
    const char *dns_server;     /* Custom DNS server (reserved for wiring; may be NULL). */
    const char *prefer_ip;      /* "4" or "6" address preference (reserved; may be NULL). */
} http_client_request_t;

/**
 * Response. status is always set on transport success; body is only set
 * in buffered mode (mode 3 above).
 */
typedef struct {
    int status;                 /* HTTP status code; 0 when the request failed. */
    char *body;                 /* NUL-terminated heap body, or NULL. */
    size_t body_len;
} http_client_response_t;

/**
 * Perform a single HTTP request.
 *
 * @param req  Request description (not modified)
 * @param resp Response output; zeroed on entry is recommended
 * @return 0 on transport success (check resp->status for the HTTP result),
 *         -1 on failure (connection, TLS, timeout, protocol error);
 *         resp->status is 0 in that case.
 */
int http_client_request(const http_client_request_t *req,
                        http_client_response_t *resp);

/**
 * Release memory owned by a response (buffered mode).
 *
 * @param resp Response previously filled by http_client_request
 */
void http_client_response_free(http_client_response_t *resp);

#endif /* KOMARI_AGENT_C_HTTP_CLIENT_H */
