/*
 * Minimal blocking HTTP/1.1 client implementation.
 *
 * Design notes:
 * - Every request uses Connection: close, so responses end at EOF or at
 *   the declared Content-Length; no keep-alive state is tracked.
 * - Response bodies are decoded for both Content-Length framing and
 *   chunked transfer encoding (GitHub's API answers with chunked).
 * - Bodies flow through one of three sinks: a caller-owned fixed buffer,
 *   a streaming writer callback (file transfers), or an internally grown
 *   heap buffer returned to the caller.
 * - TLS setup mirrors the existing per-module implementations (report.c,
 *   autodiscovery.c): verify peer by default, skip only when asked.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#include "http_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/opensslv.h>

#include "compress.h"
#include "logger.h"

/* Request header block: status line + fixed headers + extra headers. */
#define HTTP_HEADER_MAX 8192

/* Hard cap on the response header block. */
#define HTTP_HEADER_RESPONSE_MAX 16384

/* Raw socket read chunk size used while streaming the body. */
#define HTTP_RAW_BUF_SIZE 8192

/* Response codes that count as success for callers checking 2xx. */
#define HTTP_STATUS_OK_MIN 200
#define HTTP_STATUS_OK_MAX 299

/* ------------------------------------------------------------------ */
/* URL parsing                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    char scheme[16];
    char host[256];     /* Hostname or IP literal, without port or brackets. */
    int  port;
    char path[1024];    /* Path + query, always starts with '/'. */
    int  is_tls;
} http_url_t;

static int http_url_parse(const char *url, http_url_t *out) {
    if (!url || !out) return -1;
    memset(out, 0, sizeof(*out));

    const char *p = url;
    const char *scheme_end = strstr(url, "://");
    if (scheme_end) {
        size_t len = (size_t)(scheme_end - url);
        if (len == 0 || len >= sizeof(out->scheme)) return -1;
        memcpy(out->scheme, url, len);
        out->scheme[len] = '\0';
        p = scheme_end + 3;
    } else {
        snprintf(out->scheme, sizeof(out->scheme), "http");
    }

    if (strcmp(out->scheme, "https") == 0) {
        out->port = 443;
        out->is_tls = 1;
    } else if (strcmp(out->scheme, "http") == 0) {
        out->port = 80;
    } else {
        return -1;
    }

    const char *path_start = strchr(p, '/');
    if (path_start) {
        size_t host_len = (size_t)(path_start - p);
        if (host_len == 0 || host_len >= sizeof(out->host)) return -1;
        memcpy(out->host, p, host_len);
        out->host[host_len] = '\0';
        if (strlen(path_start) >= sizeof(out->path)) return -1;
        strcpy(out->path, path_start);
    } else {
        size_t host_len = strlen(p);
        if (host_len == 0 || host_len >= sizeof(out->host)) return -1;
        memcpy(out->host, p, host_len + 1);
        strcpy(out->path, "/");
    }

    /* Port: for IPv6 literals like [::1]:443 search for ':' after ']'. */
    char *colon = NULL;
    char *bracket = strchr(out->host, ']');
    if (bracket) {
        colon = strchr(bracket + 1, ':');
    } else {
        colon = strrchr(out->host, ':');
    }
    if (colon) {
        *colon = '\0';
        char *end = NULL;
        long port = strtol(colon + 1, &end, 10);
        if (!end || *end != '\0' || port <= 0 || port > 65535) return -1;
        out->port = (int)port;
    }

    /* Strip surrounding brackets from IPv6 literals for SNI/set1_host use. */
    if (out->host[0] == '[') {
        size_t len = strlen(out->host);
        if (len < 2 || out->host[len - 1] != ']') return -1;
        memmove(out->host, out->host + 1, len - 2);
        out->host[len - 2] = '\0';
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Socket / TLS plumbing                                               */
/* ------------------------------------------------------------------ */

/* Send the entire buffer over TLS or plain TCP; loops on partial writes. */
static int http_send_full(SSL *ssl, int fd, const char *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n;
        if (ssl) {
            n = SSL_write(ssl, data + sent, (int)(len - sent));
        } else {
            n = (int)send(fd, data + sent, len - sent, 0);
        }
        if (n <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Response stream: raw buffering + chunked/content-length decoding    */
/* ------------------------------------------------------------------ */

typedef struct {
    SSL *ssl;
    int fd;
    char raw[HTTP_RAW_BUF_SIZE];
    size_t raw_len;
    size_t raw_pos;
    int eof;

    int chunked;              /* Transfer-Encoding: chunked framing. */
    long chunk_remaining;     /* Bytes left in current chunk; -1 = need header. */
    long content_remaining;   /* Bytes left per Content-Length; -1 = until EOF. */
    int done;                 /* Body fully consumed. */
} http_stream_t;

static void http_stream_init(http_stream_t *s, SSL *ssl, int fd) {
    memset(s, 0, sizeof(*s));
    s->ssl = ssl;
    s->fd = fd;
    s->chunk_remaining = -1;
    s->content_remaining = -1;
}

/* Pull more raw bytes from the socket into the internal buffer.
 * Returns the number of newly available bytes, 0 on EOF, -1 on error. */
static ssize_t http_stream_fill(http_stream_t *s) {
    if (s->raw_pos < s->raw_len) return (ssize_t)(s->raw_len - s->raw_pos);
    if (s->eof || s->done) return 0;
    for (;;) {
        ssize_t n;
        if (s->ssl) {
            n = SSL_read(s->ssl, s->raw, sizeof(s->raw));
            if (n <= 0) {
                if (SSL_get_error(s->ssl, (int)n) == SSL_ERROR_ZERO_RETURN) {
                    s->eof = 1;
                    return 0;
                }
                if (errno == EINTR) continue;
                return -1;
            }
        } else {
            n = recv(s->fd, s->raw, sizeof(s->raw), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            if (n == 0) {
                s->eof = 1;
                return 0;
            }
        }
        s->raw_len = (size_t)n;
        s->raw_pos = 0;
        return n;
    }
}

/* Read one CRLF-terminated line (chunk headers) into line, stripping CRLF.
 * Returns 0 on success, -1 on EOF/error/overlong line. */
static int http_stream_read_line(http_stream_t *s, char *line, size_t cap) {
    size_t n = 0;
    for (;;) {
        if (n + 1 >= cap) return -1;
        ssize_t avail = http_stream_fill(s);
        if (avail <= 0) return -1;
        char c = s->raw[s->raw_pos++];
        if (c == '\n') {
            if (n > 0 && line[n - 1] == '\r') n--;
            line[n] = '\0';
            return 0;
        }
        line[n++] = c;
    }
}

/* Read the next decoded body chunk. Returns bytes placed in out (0 = end
 * of body, -1 = framing/IO error). */
static ssize_t http_stream_read(http_stream_t *s, char *out, size_t out_len) {
    if (s->done || out_len == 0) return 0;

    if (!s->chunked) {
        if (s->content_remaining == 0) {
            s->done = 1;
            return 0;
        }
        ssize_t n = http_stream_fill(s);
        if (n <= 0) {
            if (n == 0 && s->content_remaining < 0) {
                s->done = 1;
                return 0; /* EOF-terminated body: success. */
            }
            return n; /* Truncated Content-Length body or error. */
        }
        if (s->content_remaining >= 0 &&
            (long)n > s->content_remaining) {
            n = s->content_remaining;
        }
        memcpy(out, s->raw + s->raw_pos, (size_t)n);
        s->raw_pos += (size_t)n;
        if (s->content_remaining >= 0) s->content_remaining -= n;
        return n;
    }

    /* Chunked framing. */
    if (s->chunk_remaining < 0) {
        char line[128];
        if (http_stream_read_line(s, line, sizeof(line)) != 0) return -1;
        char *semi = strchr(line, ';');
        if (semi) *semi = '\0';
        char *end = NULL;
        long size = strtol(line, &end, 16);
        if (!end || end == line || (*end != '\0') || size < 0) return -1;
        if (size == 0) {
            /* Consume trailer lines until the blank terminator. */
            for (;;) {
                if (http_stream_read_line(s, line, sizeof(line)) != 0) return -1;
                if (line[0] == '\0') break;
            }
            s->done = 1;
            return 0;
        }
        s->chunk_remaining = size;
    }

    size_t want = out_len;
    if ((long)want > s->chunk_remaining) want = (size_t)s->chunk_remaining;
    ssize_t n = http_stream_fill(s);
    if (n <= 0) return -1; /* Truncated chunk. */
    if ((long)n > (long)want) n = (ssize_t)want;
    memcpy(out, s->raw + s->raw_pos, (size_t)n);
    s->raw_pos += (size_t)n;
    s->chunk_remaining -= n;
    if (s->chunk_remaining == 0) {
        s->chunk_remaining = -1;
        /* Consume the CRLF that terminates every chunk. */
        char line[8];
        if (http_stream_read_line(s, line, sizeof(line)) != 0) return -1;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Response header parsing helpers                                     */
/* ------------------------------------------------------------------ */

/* Case-insensitive check whether a header line's name equals name. */
static int http_header_name_is(const char *line, const char *name) {
    size_t n = strlen(name);
    if (strncasecmp(line, name, n) != 0) return 0;
    const char *p = line + n;
    while (*p == ' ' || *p == '\t') p++;
    return *p == ':';
}

static const char *http_header_value(const char *line) {
    const char *p = strchr(line, ':');
    if (!p) return "";
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

/* Portable case-insensitive substring search (strcasestr is a GNU
 * extension and not available on all supported libc builds). */
static const char *http_strcasestr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    size_t nlen = strlen(needle);
    if (nlen == 0) return haystack;
    for (; *haystack; haystack++) {
        if (strncasecmp(haystack, needle, nlen) == 0) return haystack;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Growable byte buffer (used for header block and buffered bodies)     */
/* ------------------------------------------------------------------ */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} http_buf_t;

static int http_buf_append(http_buf_t *b, const char *data, size_t len) {
    if (len == 0) return 0;
    if (b->len + len + 1 > b->cap) {
        size_t new_cap = b->cap ? b->cap : 1024;
        while (new_cap < b->len + len + 1) new_cap *= 2;
        char *nb = realloc(b->data, new_cap);
        if (!nb) return -1;
        b->data = nb;
        b->cap = new_cap;
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
    b->data[b->len] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* Request body sending                                                */
/* ------------------------------------------------------------------ */

/* Gzip an in-memory body. Returns 0 and fills out/len on success. */
static int http_gzip_body(const char *body, size_t body_len,
                          char **out, size_t *len) {
    return compress_gzip(body, body_len, out, len);
}

/* Send the request body (memory or streaming provider). Returns 0/−1. */
static int http_send_body(SSL *ssl, int fd,
                          const http_client_request_t *req,
                          const char *body_data, size_t body_len) {
    if (req->body_reader) {
        char chunk[HTTP_RAW_BUF_SIZE];
        size_t total = 0;
        for (;;) {
            ssize_t n = req->body_reader(req->body_user, chunk, sizeof(chunk));
            if (n < 0) return -1;
            if (n == 0) break;
            if (http_send_full(ssl, fd, chunk, (size_t)n) != 0) return -1;
            total += (size_t)n;
        }
        /* The Content-Length header was announced from req->body_len; the
         * provider must produce exactly that many bytes or the framing is
         * broken and the connection must be treated as failed. */
        if (req->body_len > 0 && total != req->body_len) return -1;
        return 0;
    }

    if (!body_data || body_len == 0) return 0;
    return http_send_full(ssl, fd, body_data, body_len);
}

/* ------------------------------------------------------------------ */
/* Main request routine                                                */
/* ------------------------------------------------------------------ */

int http_client_request(const http_client_request_t *req,
                        http_client_response_t *resp) {
    if (!req || !req->url || !resp) return -1;
    memset(resp, 0, sizeof(*resp));

    http_url_t url;
    if (http_url_parse(req->url, &url) != 0) {
        KOMARI_LOG_ERROR("http: invalid URL %s", req->url);
        return -1;
    }

    int timeout = req->timeout_sec > 0 ? req->timeout_sec
                                       : HTTP_CLIENT_DEFAULT_TIMEOUT_SEC;

    /* --- Resolve and connect (non-blocking connect with deadline) --- */
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", url.port);

    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(url.host, port_str, &hints, &res) != 0 || !res) {
        KOMARI_LOG_ERROR("http: DNS resolution failed host=%s", url.host);
        return -1;
    }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        struct timeval tv = {.tv_sec = timeout, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
            break;
        }
        if (errno == EINPROGRESS) {
            int connected = 0;
            time_t deadline = time(NULL) + timeout;
            for (;;) {
                time_t now = time(NULL);
                if (now >= deadline) break;
                struct pollfd pfd = {.fd = fd, .events = POLLOUT};
                int pr = poll(&pfd, 1, (int)((deadline - now) * 1000));
                if (pr < 0 && errno == EINTR) continue;
                if (pr <= 0) break;
                int so_error = 0;
                socklen_t so_len = sizeof(so_error);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len);
                if (so_error == 0) connected = 1;
                break;
            }
            if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
            if (connected) break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        KOMARI_LOG_ERROR("http: connection failed host=%s port=%d",
                         url.host, url.port);
        return -1;
    }

    /* --- TLS handshake --- */
    SSL *ssl = NULL;
    SSL_CTX *ssl_ctx = NULL;
    if (url.is_tls) {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
            close(fd);
            KOMARI_LOG_ERROR("http: SSL_CTX allocation failed");
            return -1;
        }
        if (req->ignore_cert) {
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
        } else {
            SSL_CTX_set_default_verify_paths(ssl_ctx);
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        }
        ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            SSL_CTX_free(ssl_ctx);
            close(fd);
            KOMARI_LOG_ERROR("http: SSL allocation failed");
            return -1;
        }
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, url.host);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        if (!req->ignore_cert) {
            SSL_set1_host(ssl, url.host);
        }
#endif
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ssl_ctx);
            close(fd);
            KOMARI_LOG_ERROR("http: TLS handshake failed host=%s", url.host);
            return -1;
        }
    }

    int ret = -1;
    char *send_buf = NULL;
    char *gz_body = NULL;
    size_t gz_len = 0;
    http_buf_t hdr = {0};
    http_stream_t stream;
    char *acc = NULL;          /* Buffered-mode accumulator. */
    size_t acc_len = 0, acc_cap = 0;

    /* --- Normalize the body and compress it when requested. --- */
    const char *body_data = req->body;
    size_t body_len = req->body_len;
    if (req->body && !req->body_reader && body_len == 0) {
        body_len = strlen(req->body);
    }
    if (req->gzip_body && req->body) {
        if (http_gzip_body(req->body, body_len, &gz_body, &gz_len) != 0) {
            KOMARI_LOG_ERROR("http: gzip compression failed");
            goto out;
        }
        body_data = gz_body;
        body_len = gz_len;
    }
    /* Content-Length: for streaming providers this is the caller-declared
     * total (req->body_len); otherwise it is the actual body size. */
    size_t declared = req->body_reader ? req->body_len : body_len;

    /* Host header value: bracket IPv6 literals, omit default ports. */
    int default_port = (url.is_tls && url.port == 443) ||
                       (!url.is_tls && url.port == 80);
    char host_header[300];
    if (default_port) {
        if (strchr(url.host, ':')) {
            snprintf(host_header, sizeof(host_header), "[%s]", url.host);
        } else {
            snprintf(host_header, sizeof(host_header), "%s", url.host);
        }
    } else {
        if (strchr(url.host, ':')) {
            snprintf(host_header, sizeof(host_header), "[%s]:%d", url.host, url.port);
        } else {
            snprintf(host_header, sizeof(host_header), "%s:%d", url.host, url.port);
        }
    }

    /* --- Build and send the request head. --- */
    const char *method = req->method ? req->method : "POST";
    const char *content_type = req->content_type ? req->content_type
                                                 : "application/json";

    send_buf = malloc(HTTP_HEADER_MAX);
    if (!send_buf) goto out;
    int head = snprintf(send_buf, HTTP_HEADER_MAX,
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: komari-agent-c\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n",
        method, url.path, host_header,
        content_type, declared);
    if (head < 0 || head >= HTTP_HEADER_MAX) {
        KOMARI_LOG_ERROR("http: request head too long");
        goto out;
    }
    if (req->gzip_body && req->body) {
        int n = snprintf(send_buf + head, HTTP_HEADER_MAX - head,
                         "Content-Encoding: gzip\r\n");
        if (n < 0 || head + n >= HTTP_HEADER_MAX) goto out;
        head += n;
    }
    if (req->extra_headers && req->extra_headers[0]) {
        int n = snprintf(send_buf + head, HTTP_HEADER_MAX - head, "%s",
                         req->extra_headers);
        if (n < 0 || head + n >= HTTP_HEADER_MAX) goto out;
        head += n;
    }
    if (head + 2 >= HTTP_HEADER_MAX) goto out;
    send_buf[head++] = '\r';
    send_buf[head++] = '\n';

    if (http_send_full(ssl, fd, send_buf, (size_t)head) != 0 ||
        http_send_body(ssl, fd, req, body_data, body_len) != 0) {
        KOMARI_LOG_ERROR("http: failed to send request to %s", url.host);
        goto out;
    }

    /* --- Read the response header block. --- */
    http_stream_init(&stream, ssl, fd);
    size_t scan_from = 0;
    for (;;) {
        ssize_t n = http_stream_fill(&stream);
        if (n <= 0) {
            KOMARI_LOG_ERROR("http: no/short response from %s", url.host);
            goto out;
        }
        if (http_buf_append(&hdr, stream.raw + stream.raw_pos, (size_t)n) != 0) {
            goto out;
        }
        stream.raw_pos += (size_t)n;
        if (hdr.len >= HTTP_HEADER_RESPONSE_MAX) {
            KOMARI_LOG_ERROR("http: response header block too large");
            goto out;
        }
        /* Scan for the empty line terminating the header block. */
        if (hdr.len >= 4) {
            size_t from = scan_from;
            if (from + 3 > hdr.len) from = hdr.len >= 4 ? hdr.len - 4 : 0;
            const char *sep = NULL;
            for (size_t i = from; i + 4 <= hdr.len; i++) {
                if (hdr.data[i] == '\r' && hdr.data[i + 1] == '\n' &&
                    hdr.data[i + 2] == '\r' && hdr.data[i + 3] == '\n') {
                    sep = hdr.data + i;
                    break;
                }
            }
            if (sep) {
                size_t leftover = hdr.len - (size_t)(sep - hdr.data) - 4;
                if (leftover > 0) {
                    memcpy(stream.raw, sep + 4, leftover);
                    stream.raw_len = leftover;
                    stream.raw_pos = 0;
                } else {
                    stream.raw_len = 0;
                    stream.raw_pos = 0;
                }
                hdr.len = (size_t)(sep - hdr.data);
                hdr.data[hdr.len] = '\0';
                break;
            }
            scan_from = hdr.len >= 3 ? hdr.len - 3 : 0;
        }
    }

    /* --- Parse status line and framing headers. --- */
    if (strncmp(hdr.data, "HTTP/1.", 7) != 0 || hdr.len < 12) {
        KOMARI_LOG_ERROR("http: malformed status line");
        goto out;
    }
    int status = atoi(hdr.data + 9);
    if (status < 100 || status > 599) {
        KOMARI_LOG_ERROR("http: invalid status code");
        goto out;
    }
    resp->status = status;

    int chunked = 0, gzipped = 0;
    long content_length = -1;
    char *save = NULL;
    /* Walk header lines; the first line is the status line. */
    for (char *line = strtok_r(hdr.data, "\r\n", &save); line;
         line = strtok_r(NULL, "\r\n", &save)) {
        if (line == hdr.data) continue;
        if (http_header_name_is(line, "Transfer-Encoding")) {
            if (http_strcasestr(http_header_value(line), "chunked")) chunked = 1;
        } else if (http_header_name_is(line, "Content-Length")) {
            content_length = strtol(http_header_value(line), NULL, 10);
            if (content_length < 0) content_length = -1;
        } else if (http_header_name_is(line, "Content-Encoding")) {
            if (http_strcasestr(http_header_value(line), "gzip")) gzipped = 1;
        }
    }
    (void)gzipped; /* Only consumed in buffered mode below. */

    stream.chunked = chunked;
    if (!chunked && content_length >= 0) stream.content_remaining = content_length;

    /* --- Stream the body into the requested sink. --- */
    if (req->body_writer) {
        char tmp[HTTP_RAW_BUF_SIZE];
        for (;;) {
            ssize_t n = http_stream_read(&stream, tmp, sizeof(tmp));
            if (n < 0) {
                KOMARI_LOG_ERROR("http: body read error");
                goto out;
            }
            if (n == 0) break;
            if (req->body_writer(req->writer_user, tmp, (size_t)n) != 0) {
                goto out;
            }
        }
    } else if (req->response_buf && req->response_len > 0) {
        size_t cap = req->response_len - 1;
        size_t total = 0;
        while (total < cap) {
            ssize_t n = http_stream_read(&stream, req->response_buf + total,
                                         cap - total);
            if (n < 0) goto out;
            if (n == 0) break;
            total += (size_t)n;
        }
        req->response_buf[total] = '\0';
    } else {
        size_t max_resp = req->max_response ? req->max_response
                                            : HTTP_CLIENT_DEFAULT_MAX_RESPONSE;
        acc_cap = 4096;
        acc = malloc(acc_cap);
        if (!acc) goto out;
        char tmp[HTTP_RAW_BUF_SIZE];
        for (;;) {
            ssize_t n = http_stream_read(&stream, tmp, sizeof(tmp));
            if (n < 0) goto out;
            if (n == 0) break;
            if (acc_len + (size_t)n > max_resp) {
                KOMARI_LOG_ERROR("http: response body exceeds %zu bytes", max_resp);
                goto out;
            }
            /* Grow the accumulator to fit the incoming chunk (plus NUL). */
            if (acc_len + (size_t)n + 1 > acc_cap) {
                size_t new_cap = acc_cap;
                while (acc_len + (size_t)n + 1 > new_cap) new_cap *= 2;
                if (new_cap > max_resp + 1) new_cap = max_resp + 1;
                char *nb = realloc(acc, new_cap);
                if (!nb) goto out;
                acc = nb;
                acc_cap = new_cap;
            }
            memcpy(acc + acc_len, tmp, (size_t)n);
            acc_len += (size_t)n;
        }
        acc[acc_len] = '\0';
    }

    ret = 0;

out:
    /* Transport-level success: hand over the buffered body (and decode
     * gzip when the server ignored our implicit identity preference). */
    if (ret == 0 && acc) {
        char *final_body = acc;
        size_t final_len = acc_len;
        if (gzipped && acc_len > 0) {
            char *plain = NULL;
            size_t plain_len = 0;
            if (compress_gunzip(acc, acc_len, &plain, &plain_len) == 0) {
                final_body = plain;
                final_len = plain_len;
            } else {
                KOMARI_LOG_WARN("http: gzip response decoding failed, returning raw body");
            }
        }
        resp->body = final_body;
        resp->body_len = final_len;
    } else {
        free(acc);
    }
    if (ret != 0) resp->status = 0;
    free(hdr.data);
    free(send_buf);
    free(gz_body);
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    close(fd);
    return ret;
}

void http_client_response_free(http_client_response_t *resp) {
    if (!resp) return;
    free(resp->body);
    resp->body = NULL;
    resp->body_len = 0;
}
