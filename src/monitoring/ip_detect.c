/*
 * Public IP detection implementation.
 *
 * Each detection API is fetched over a socket bound to the requested address
 * family (tcp4 for IPv4, tcp6 for IPv6) with a 15-second overall timeout and
 * the User-Agent the Go reference uses (curl/8.0.1). The address is then
 * extracted with a simple textual scan of the response body, which is how
 * the Go reference behaves for these endpoints.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#include "ip_detect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/opensslv.h>

#include "logger.h"
#include "monitoring.h"

/* IPv4 detection APIs in priority order (ip.go ipv4APIs). */
static const char *const IPV4_APIS[] = {
    "https://www.visa.cn/cdn-cgi/trace",
    "https://www.qualcomm.cn/cdn-cgi/trace",
    "https://www.toutiao.com/stream/widget/local_weather/data/",
    "https://edge-ip.html.zone/geo",
    "https://vercel-ip.html.zone/geo",
    "http://ipv4.ip.sb",
    "https://api.ipify.org?format=json",
};
#define IPV4_APIS_COUNT (int)(sizeof(IPV4_APIS) / sizeof(IPV4_APIS[0]))

/* IPv6 detection APIs in priority order (ip.go ipv6APIs). */
static const char *const IPV6_APIS[] = {
    "https://v6.ip.zxinc.org/info.php?type=json",
    "https://api6.ipify.org?format=json",
    "https://ipv6.icanhazip.com",
    "http://api-ipv6.ip.sb/geoip",
};
#define IPV6_APIS_COUNT (int)(sizeof(IPV6_APIS) / sizeof(IPV6_APIS[0]))

#define IP_DETECT_TIMEOUT_SEC 15
#define IP_DETECT_UA "User-Agent: curl/8.0.1\r\n"
#define IP_DETECT_BUF 4096

/* ------------------------------------------------------------------ */
/* URL parsing (same shape as http_client; local copy keeps the probe  */
/* self-contained without depending on family-forced sockets).         */
/* ------------------------------------------------------------------ */

typedef struct {
    char host[256];
    int port;
    char path[512];
    int is_tls;
} ip_url_t;

static int ip_url_parse(const char *url, ip_url_t *out) {
    memset(out, 0, sizeof(*out));
    const char *p = strstr(url, "://");
    if (!p) return -1;
    size_t scheme_len = (size_t)(p - url);
    out->is_tls = (scheme_len == 5 && strncmp(url, "https", 5) == 0);
    if (!out->is_tls && !(scheme_len == 4 && strncmp(url, "http", 4) == 0)) {
        return -1;
    }
    out->port = out->is_tls ? 443 : 80;
    p += 3;

    const char *path_start = strchr(p, '/');
    if (path_start) {
        size_t hlen = (size_t)(path_start - p);
        if (hlen == 0 || hlen >= sizeof(out->host)) return -1;
        memcpy(out->host, p, hlen);
        out->host[hlen] = '\0';
        snprintf(out->path, sizeof(out->path), "%s", path_start);
    } else {
        snprintf(out->host, sizeof(out->host), "%s", p);
        strcpy(out->path, "/");
    }

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
    /* Strip brackets from IPv6 literals. */
    if (out->host[0] == '[') {
        size_t len = strlen(out->host);
        if (len < 2 || out->host[len - 1] != ']') return -1;
        memmove(out->host, out->host + 1, len - 2);
        out->host[len - 2] = '\0';
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Minimal HTTPS/HTTP GET with a forced address family                 */
/* ------------------------------------------------------------------ */

/* Fetch a URL over the given address family (AF_INET / AF_INET6) and copy
 * the response body into body_out. Returns 0 on success. */
static int ip_fetch(const char *url, int family, char *body_out, size_t body_len) {
    ip_url_t u;
    if (ip_url_parse(url, &u) != 0) return -1;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", u.port);

    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family; /* Force v4 or v6, mirroring Go's tcp4/tcp6. */
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(u.host, port_str, &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    time_t deadline = time(NULL) + IP_DETECT_TIMEOUT_SEC;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int connected = 0;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            connected = 1;
        } else if (errno == EINPROGRESS) {
            while (time(NULL) < deadline) {
                struct pollfd pfd = {.fd = fd, .events = POLLOUT};
                int pr = poll(&pfd, 1, 1000);
                if (pr > 0) {
                    int so_error = 0;
                    socklen_t slen = sizeof(so_error);
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &slen);
                    if (so_error == 0) connected = 1;
                    break;
                }
                if (pr < 0 && errno == EINTR) continue;
                break;
            }
        }
        if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        if (connected) break;

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    struct timeval tv = {.tv_sec = IP_DETECT_TIMEOUT_SEC, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    if (u.is_tls) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { close(fd); return -1; }
        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        ssl = SSL_new(ctx);
        if (!ssl) { SSL_CTX_free(ctx); close(fd); return -1; }
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, u.host);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        SSL_set1_host(ssl, u.host);
#endif
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(fd);
            return -1;
        }
    }

    char request[1024];
    int rn = snprintf(request, sizeof(request),
                      "GET %s HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      IP_DETECT_UA
                      "Accept: */*\r\n"
                      "Accept-Encoding: identity\r\n"
                      "Connection: close\r\n"
                      "\r\n",
                      u.path, u.host);
    int ret = -1;
    if (rn > 0 && (size_t)rn < sizeof(request)) {
        /* Send (full) */
        size_t sent = 0;
        int send_ok = 1;
        while (sent < (size_t)rn) {
            int n = ssl ? SSL_write(ssl, request + sent, (int)((size_t)rn - sent))
                        : (int)send(fd, request + sent, (size_t)rn - sent, 0);
            if (n <= 0) { if (errno == EINTR) continue; send_ok = 0; break; }
            sent += (size_t)n;
        }
        if (send_ok) {
            /* Read the whole response (Connection: close bounds it). */
            char *raw = malloc(IP_DETECT_BUF);
            if (raw) {
                size_t total = 0;
                for (;;) {
                    if (total >= IP_DETECT_BUF - 1) break;
                    ssize_t n = ssl
                        ? SSL_read(ssl, raw + total, IP_DETECT_BUF - 1 - total)
                        : recv(fd, raw + total, IP_DETECT_BUF - 1 - total, 0);
                    if (n <= 0) {
                        if (n < 0 && !ssl && errno == EINTR) continue;
                        break;
                    }
                    total += (size_t)n;
                }
                raw[total] = '\0';
                const char *body = strstr(raw, "\r\n\r\n");
                if (body) {
                    body += 4;
                    snprintf(body_out, body_len, "%s", body);
                    ret = 0;
                }
                free(raw);
            }
        }
    }

    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) SSL_CTX_free(ctx);
    close(fd);
    return ret;
}

/* Extract the first IPv4 dotted-quad from a response body. */
static int ip_extract_ipv4(const char *body, char *out, size_t out_len) {
    for (const char *p = body; *p; p++) {
        if (!isdigit((unsigned char)*p)) continue;
        unsigned a, b, c, d;
        char endc;
        if (sscanf(p, "%u.%u.%u.%u%c", &a, &b, &c, &d, &endc) >= 4 &&
            a <= 255 && b <= 255 && c <= 255 && d <= 255) {
            /* Reject matches that are part of a longer numeric token. */
            if (p > body && (isdigit((unsigned char)p[-1]))) continue;
            int n = snprintf(out, out_len, "%u.%u.%u.%u", a, b, c, d);
            return (n > 0 && (size_t)n < out_len) ? 0 : -1;
        }
    }
    return -1;
}

/* Extract the first plausible IPv6 address (hex runs with colons) from the
 * response body, skipping very short tokens. */
static int ip_extract_ipv6(const char *body, char *out, size_t out_len) {
    const char *p = body;
    while (*p) {
        if (isxdigit((unsigned char)*p)) {
            const char *start = p;
            int colons = 0, hexchars = 0;
            while (*p && (isxdigit((unsigned char)*p) || *p == ':' || *p == '.')) {
                if (*p == ':') colons++;
                else if (*p != '.') hexchars++;
                p++;
            }
            /* A compressed form may have as few as 2 colons (::1); require
             * at least 2 hex chars and 2 colons to avoid JSON noise. */
            if (colons >= 2 && hexchars >= 2 &&
                (size_t)(p - start) < out_len) {
                memcpy(out, start, p - start);
                out[p - start] = '\0';
                /* Validate via inet_pton. */
                struct in6_addr tmp;
                if (inet_pton(AF_INET6, out, &tmp) == 1) return 0;
            }
        } else {
            p++;
        }
    }
    return -1;
}

int ip_detect_ipv4_api(char *out, size_t out_len) {
    if (!out || out_len == 0) return -1;
    out[0] = '\0';
    for (int i = 0; i < IPV4_APIS_COUNT; i++) {
        char body[IP_DETECT_BUF];
        if (ip_fetch(IPV4_APIS[i], AF_INET, body, sizeof(body)) == 0 &&
            ip_extract_ipv4(body, out, out_len) == 0) {
            return 0;
        }
    }
    return -1;
}

int ip_detect_ipv6_api(char *out, size_t out_len) {
    if (!out || out_len == 0) return -1;
    out[0] = '\0';
    for (int i = 0; i < IPV6_APIS_COUNT; i++) {
        char body[IP_DETECT_BUF];
        if (ip_fetch(IPV6_APIS[i], AF_INET6, body, sizeof(body)) == 0 &&
            ip_extract_ipv6(body, out, out_len) == 0) {
            return 0;
        }
    }
    return -1;
}

void ip_detect_public(bool get_from_nic, const char *custom_ipv4,
                      const char *custom_ipv6,
                      char *ipv4_out, size_t ipv4_len,
                      char *ipv6_out, size_t ipv6_len) {
    if (ipv4_out && ipv4_len > 0) ipv4_out[0] = '\0';
    if (ipv6_out && ipv6_len > 0) ipv6_out[0] = '\0';

    /* 1. NIC path: reuse monitoring_get_ip_address (getifaddrs with virtual
     * interface filtering). Mirrors the Go get_ip_addr_from_nic behavior of
     * returning early with whatever the NICs yield. */
    if (get_from_nic) {
        char nic_v4[64] = "", nic_v6[128] = "";
        if (monitoring_get_ip_address(nic_v4, sizeof(nic_v4),
                                      nic_v6, sizeof(nic_v6)) == 0) {
            if (ipv4_out && nic_v4[0]) snprintf(ipv4_out, ipv4_len, "%s", nic_v4);
            if (ipv6_out && nic_v6[0]) snprintf(ipv6_out, ipv6_len, "%s", nic_v6);
            if ((ipv4_out && ipv4_out[0]) || (ipv6_out && ipv6_out[0])) {
                return;
            }
        }
    }

    /* 2. Custom overrides (Go ip.go CustomIpv4/CustomIpv6). */
    if (ipv4_out && custom_ipv4 && custom_ipv4[0]) {
        snprintf(ipv4_out, ipv4_len, "%s", custom_ipv4);
    }
    if (ipv6_out && custom_ipv6 && custom_ipv6[0]) {
        snprintf(ipv6_out, ipv6_len, "%s", custom_ipv6);
    }
    if ((ipv4_out && ipv4_out[0]) || (ipv6_out && ipv6_out[0])) {
        /* Fill whichever is still missing from the Web API below. */
    }

    /* 3. Web APIs for the addresses still missing. */
    if (ipv4_out && !ipv4_out[0]) {
        ip_detect_ipv4_api(ipv4_out, ipv4_len);
    }
    if (ipv6_out && !ipv6_out[0]) {
        ip_detect_ipv6_api(ipv6_out, ipv6_len);
    }
}
