/*
 * test_http_client.c - HTTP client unit tests against a loopback server
 *
 * Test scope:
 *   - Basic POST with Content-Length response framing
 *   - Chunked transfer-encoding decoding
 *   - Status code passthrough (success and error codes)
 *   - Streaming response writer sink
 *   - Streaming request body provider with declared Content-Length
 *   - gzip request body (Content-Encoding header + gzip magic bytes)
 *
 * The tests spin up a minimal TCP server on a loopback port inside a
 * helper thread; no external network access is required.
 */

#include "unity.h"
#include "http_client.h"
#include "logger.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_RECV 65536
#define LARGE_BODY_LEN 100000

typedef struct {
    int listen_fd;
    int port;
    const char *response;      /* Raw HTTP response bytes to send back. */
    size_t response_len;
    char received[MAX_RECV];   /* Captured request bytes. */
    size_t received_len;
    int done;
} server_ctx_t;

/* Extract a header value from the captured request (case-insensitive name,
 * returns pointer into the request buffer or NULL). */
static const char *find_header(const char *req, const char *name) {
    size_t nlen = strlen(name);
    const char *p = req;
    while (p && *p) {
        const char *eol = strstr(p, "\r\n");
        size_t line_len = eol ? (size_t)(eol - p) : strlen(p);
        if (line_len > nlen && strncasecmp(p, name, nlen) == 0 &&
            p[nlen] == ':') {
            const char *v = p + nlen + 1;
            while (*v == ' ') v++;
            return v;
        }
        p = eol ? eol + 2 : NULL;
    }
    return NULL;
}

static void *server_thread(void *arg) {
    server_ctx_t *ctx = (server_ctx_t *)arg;
    /* Accept up to 5 connections so a client retry after a transport
     * hiccup still gets a valid response. */
    for (int conn_no = 0; conn_no < 5; conn_no++) {
        int conn = accept(ctx->listen_fd, NULL, NULL);
        if (conn < 0) return NULL;

        /* Read the request: headers, then the declared Content-Length body. */
        size_t total = 0;
        size_t body_start = 0;
        long content_len = -1;
        while (total < sizeof(ctx->received) - 1) {
            ssize_t n = recv(conn, ctx->received + total,
                             sizeof(ctx->received) - 1 - total, 0);
            if (n <= 0) break;
            total += (size_t)n;
            ctx->received[total] = '\0';
            if (body_start == 0) {
                char *sep = strstr(ctx->received, "\r\n\r\n");
                if (sep) {
                    body_start = (size_t)(sep - ctx->received) + 4;
                    const char *cl = find_header(ctx->received, "Content-Length");
                    content_len = cl ? strtol(cl, NULL, 10) : 0;
                }
            }
            if (body_start > 0 && content_len >= 0 &&
                total >= body_start + (size_t)content_len) {
                break;
            }
        }
        ctx->received_len = total;
        ctx->received[total] = '\0';

        if (ctx->response_len > 0) {
            size_t sent = 0;
            while (sent < ctx->response_len) {
                ssize_t n = send(conn, ctx->response + sent,
                                 ctx->response_len - sent, 0);
                if (n <= 0) break;
                sent += (size_t)n;
            }
        }
        shutdown(conn, SHUT_WR);
        close(conn);
        ctx->done = 1;
    }
    return NULL;
}

/* Start the loopback server; returns the chosen port via ctx->port. */
static void start_server(server_ctx_t *ctx, const char *response) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->response = response;
    ctx->response_len = response ? strlen(response) : 0;

    ctx->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT_TRUE(ctx->listen_fd >= 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    TEST_ASSERT_EQUAL_INT(0, bind(ctx->listen_fd, (struct sockaddr *)&addr,
                                  sizeof(addr)));
    TEST_ASSERT_EQUAL_INT(0, listen(ctx->listen_fd, 1));

    socklen_t len = sizeof(addr);
    TEST_ASSERT_EQUAL_INT(0, getsockname(ctx->listen_fd, (struct sockaddr *)&addr, &len));
    ctx->port = ntohs(addr.sin_port);

    pthread_t tid;
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&tid, NULL, server_thread, ctx));
    pthread_detach(tid);
}

static void stop_server(server_ctx_t *ctx) {
    close(ctx->listen_fd);
}

/* Build the loopback URL for the test server into buf. */
static void make_url(server_ctx_t *ctx, char *buf, size_t cap) {
    snprintf(buf, cap, "http://127.0.0.1:%d/", ctx->port);
}

void setUp(void) {
    /* Enable stdout logging so http_client error paths are visible when
     * a test fails (logger drops output when never initialized). */
    logger_config_t cfg = {0};
    cfg.level = LOG_LEVEL_DEBUG;
    cfg.use_stdout = true;
    cfg.tag = (char *)"test-http";
    logger_init(&cfg);
}

void tearDown(void) {
    logger_cleanup();
}

/* ====== basic POST / Content-Length framing ====== */

void test_http_post_basic(void) {
    server_ctx_t srv;
    start_server(&srv, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    char url[64];
    make_url(&srv, url, sizeof(url));

    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body = "payload";

    /* First attempt may race the accept(); retry a few times. */
    int ret = -1;
    for (int attempt = 0; attempt < 10; attempt++) {
        usleep(20000);
        ret = http_client_request(&req, &resp);
        if (ret == 0) break;
        memset(&resp, 0, sizeof(resp));
    }
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(200, resp.status);
    TEST_ASSERT_NOT_NULL(resp.body);
    TEST_ASSERT_EQUAL_STRING("ok", resp.body);

    TEST_ASSERT_NOT_NULL(strstr(srv.received, "POST / HTTP/1.1\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(srv.received, "Content-Length: 7\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(srv.received, "Connection: close\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(srv.received, "\r\npayload"));

    http_client_response_free(&resp);
    stop_server(&srv);
}

/* ====== chunked transfer decoding ====== */

void test_http_chunked_response(void) {
    server_ctx_t srv;
    start_server(&srv,
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\nWiki\r\n"
        "5\r\npedia\r\n"
        "0\r\n\r\n");
    char url[64];
    make_url(&srv, url, sizeof(url));

    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body = "";
    int ret = -1;
    for (int attempt = 0; attempt < 10; attempt++) {
        usleep(20000);
        ret = http_client_request(&req, &resp);
        if (ret == 0) break;
        memset(&resp, 0, sizeof(resp));
    }
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(200, resp.status);
    TEST_ASSERT_EQUAL_STRING("Wikipedia", resp.body);

    http_client_response_free(&resp);
    stop_server(&srv);
}

/* ====== non-2xx status passthrough ====== */

void test_http_status_404(void) {
    server_ctx_t srv;
    start_server(&srv, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    char url[64];
    make_url(&srv, url, sizeof(url));

    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body = "";
    int ret = -1;
    for (int attempt = 0; attempt < 10; attempt++) {
        usleep(20000);
        ret = http_client_request(&req, &resp);
        if (ret == 0) break;
        memset(&resp, 0, sizeof(resp));
    }
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(404, resp.status);

    http_client_response_free(&resp);
    stop_server(&srv);
}

/* ====== streaming response writer ====== */

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} acc_writer_t;

static int acc_writer(void *user, const char *data, size_t len) {
    acc_writer_t *acc = (acc_writer_t *)user;
    if (acc->len + len > acc->cap) return -1;
    memcpy(acc->buf + acc->len, data, len);
    acc->len += len;
    return 0;
}

void test_http_streaming_response_writer(void) {
    /* Build a Content-Length response carrying 100000 'A' bytes. */
    char *response = malloc(4096 + LARGE_BODY_LEN);
    TEST_ASSERT_NOT_NULL(response);
    int n = snprintf(response, 4096,
                     "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n",
                     LARGE_BODY_LEN);
    memset(response + n, 'A', LARGE_BODY_LEN);

    server_ctx_t srv;
    start_server(&srv, response);
    char url[64];
    make_url(&srv, url, sizeof(url));
    srv.response_len = (size_t)n + LARGE_BODY_LEN;

    acc_writer_t acc;
    acc.buf = malloc(LARGE_BODY_LEN);
    acc.len = 0;
    acc.cap = LARGE_BODY_LEN;
    TEST_ASSERT_NOT_NULL(acc.buf);

    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body = "";
    req.body_writer = acc_writer;
    req.writer_user = &acc;

    int ret = -1;
    for (int attempt = 0; attempt < 10; attempt++) {
        usleep(20000);
        ret = http_client_request(&req, &resp);
        if (ret == 0) break;
    }
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(200, resp.status);
    TEST_ASSERT_EQUAL_size_t(LARGE_BODY_LEN, acc.len);
    TEST_ASSERT_EQUAL_MEMORY("AAAA", acc.buf, 4);
    TEST_ASSERT_NULL(resp.body);

    free(response);
    free(acc.buf);
    stop_server(&srv);
}

/* ====== streaming request body provider ====== */

typedef struct {
    const char *data;
    size_t len;
    size_t pos;
} body_source_t;

static ssize_t body_source_read(void *user, char *buf, size_t len) {
    body_source_t *src = (body_source_t *)user;
    if (src->pos >= src->len) return 0;
    size_t n = src->len - src->pos;
    if (n > len) n = len;
    if (n > 3) n = 3; /* Tiny chunks to exercise the provider loop. */
    memcpy(buf, src->data + src->pos, n);
    src->pos += n;
    return (ssize_t)n;
}

void test_http_body_provider(void) {
    server_ctx_t srv;
    start_server(&srv, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    char url[64];
    make_url(&srv, url, sizeof(url));

    body_source_t src = {.data = "hello world", .len = 11, .pos = 0};
    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body_reader = body_source_read;
    req.body_user = &src;
    req.body_len = 11;
    req.content_type = "application/octet-stream";

    int ret = -1;
    for (int attempt = 0; attempt < 10; attempt++) {
        usleep(20000);
        ret = http_client_request(&req, &resp);
        if (ret == 0) break;
    }
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(200, resp.status);

    /* The server must have received the exact body bytes and the declared
     * Content-Length header. */
    const char *cl = find_header(srv.received, "Content-Length");
    TEST_ASSERT_NOT_NULL(cl);
    TEST_ASSERT_EQUAL_INT(11, atoi(cl));
    char *sep = strstr(srv.received, "\r\n\r\n");
    TEST_ASSERT_NOT_NULL(sep);
    TEST_ASSERT_EQUAL_MEMORY("hello world", sep + 4, 11);

    http_client_response_free(&resp);
    stop_server(&srv);
}

/* ====== gzip request body ====== */

void test_http_gzip_request_body(void) {
    server_ctx_t srv;
    start_server(&srv, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    char url[64];
    make_url(&srv, url, sizeof(url));

    const char *payload =
        "compressible payload repeated repeated repeated repeated repeated";
    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body = payload;
    req.gzip_body = 1;

    int ret = -1;
    for (int attempt = 0; attempt < 10; attempt++) {
        usleep(20000);
        ret = http_client_request(&req, &resp);
        if (ret == 0) break;
    }
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(200, resp.status);

    TEST_ASSERT_NOT_NULL(strstr(srv.received, "Content-Encoding: gzip\r\n"));
    char *sep = strstr(srv.received, "\r\n\r\n");
    TEST_ASSERT_NOT_NULL(sep);
    /* gzip magic bytes 1f 8b must open the body. */
    TEST_ASSERT_EQUAL_UINT8(0x1F, (unsigned char)sep[4]);
    TEST_ASSERT_EQUAL_UINT8(0x8B, (unsigned char)sep[5]);

    http_client_response_free(&resp);
    stop_server(&srv);
}

/* ====== fixed response buffer mode ====== */

void test_http_fixed_response_buffer(void) {
    server_ctx_t srv;
    start_server(&srv, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    char url[64];
    make_url(&srv, url, sizeof(url));

    char buf[64];
    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body = "";
    req.url = url;
    req.response_buf = buf;
    req.response_len = sizeof(buf);

    int ret = -1;
    for (int attempt = 0; attempt < 10; attempt++) {
        usleep(20000);
        ret = http_client_request(&req, &resp);
        if (ret == 0) break;
    }
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(200, resp.status);
    TEST_ASSERT_EQUAL_STRING("hello", buf);
    TEST_ASSERT_NULL(resp.body);

    http_client_response_free(&resp);
    stop_server(&srv);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_http_post_basic);
    RUN_TEST(test_http_chunked_response);
    RUN_TEST(test_http_status_404);
    RUN_TEST(test_http_streaming_response_writer);
    RUN_TEST(test_http_body_provider);
    RUN_TEST(test_http_gzip_request_body);
    RUN_TEST(test_http_fixed_response_buffer);

    return UNITY_END();
}
