/*
 * POST fallback channel implementation over http_client.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#include "fallback.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compress.h"
#include "http_client.h"
#include "logger.h"
#include "jsonrpc.h"
#include "v2.h"

/* URL-encode a string for safe inclusion in a URL query parameter value
 * (mirrors the helpers in report.c/autodiscovery.c; no shared private
 * header exists for it). Returns the encoded length, or -1 when the
 * destination buffer is too small. */
static int url_encode(const char *src, char *dst, size_t dst_len) {
    if (!src || !dst || dst_len == 0) return -1;
    static const char hex[] = "0123456789ABCDEF";
    size_t j = 0;
    for (size_t i = 0; src[i]; i++) {
        unsigned char c = (unsigned char)src[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            if (j + 1 >= dst_len) return -1;
            dst[j++] = (char)c;
        } else {
            if (j + 3 >= dst_len) return -1;
            dst[j++] = '%';
            dst[j++] = hex[(c >> 4) & 0xF];
            dst[j++] = hex[c & 0xF];
        }
    }
    dst[j] = '\0';
    return (int)j;
}

/* Shared URL builder: "<endpoint>/api/clients/v2/rpc?token=<encoded>".
 * Duplicated from report.c which keeps its own static copy; both live in
 * translation units without a shared private header. */
static int build_rpc_url(const agent_config_t *config, char *url, size_t url_len) {
    char encoded_token[MAX_TOKEN_LEN * 3 + 1];
    if (url_encode(config->token, encoded_token, sizeof(encoded_token)) < 0) {
        return -1;
    }
    int n = snprintf(url, url_len, "%s%s?token=%s",
                     config->endpoint, V2_RPC_ENDPOINT, encoded_token);
    return (n < 0 || (size_t)n >= url_len) ? -1 : 0;
}

int fallback_post_rpc(const agent_config_t *config, const char *request_body,
                      bool gzip, int timeout_sec, cJSON **response_out) {
    if (!config || !request_body || !response_out) return -1;
    *response_out = NULL;

    char url[MAX_ENDPOINT_LEN + 64 + MAX_TOKEN_LEN * 3 + 1];
    if (build_rpc_url(config, url, sizeof(url)) != 0) {
        return -1;
    }

    const char *body = request_body;
    size_t body_len = strlen(request_body);
    char *gz = NULL;
    size_t gz_len = 0;
    if (gzip && compress_gzip(request_body, body_len, &gz, &gz_len) == 0) {
        body = gz;
        body_len = gz_len;
    }

    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body = body;
    req.body_len = body_len;
    req.gzip_body = 0; /* Pre-compressed above; header added below when set. */
    req.ignore_cert = config->ignore_unsafe_cert;
    req.timeout_sec = timeout_sec;
    req.extra_headers = (body != request_body) ? "Content-Encoding: gzip\r\n" : NULL;

    int ret = -1;
    if (http_client_request(&req, &resp) == 0 &&
        resp.status >= 200 && resp.status < 300) {
        ret = 0;
        if (resp.body && resp.body_len > 0) {
            *response_out = cJSON_Parse(resp.body);
        }
    }
    http_client_response_free(&resp);
    free(gz);
    return ret;
}

int fallback_build_report_request(long report_id, const char *report_body,
                                  const int *ack_ids, int ack_count, char **out) {
    if (!report_body || !out) return -1;
    *out = NULL;

    /* The report body is pre-escaped, complete JSON, so it is embedded
     * verbatim under params.report (same trick as report_generate_v2). */
    size_t cap = strlen(report_body) + 256 + (ack_count > 0 ? (size_t)ack_count * 12 : 0);
    char *buf = malloc(cap);
    if (!buf) return -1;

    int offset = snprintf(buf, cap,
                          "{\"jsonrpc\":\"2.0\",\"id\":\"report-%ld\","
                          "\"method\":\"%s\",\"params\":{\"report\":",
                          report_id, AGENT_REPORT);
    if (offset < 0 || (size_t)offset >= cap) {
        free(buf);
        return -1;
    }

    size_t blen = strlen(report_body);
    if (offset + (int)blen + 2 >= (int)cap) {
        free(buf);
        return -1;
    }
    memcpy(buf + offset, report_body, blen);
    offset += (int)blen;
    buf[offset++] = '}';
    buf[offset++] = '}';

    /* Append ack_event_ids after params.report, keeping params open. */
    /* The closing braces above close params and envelope only when no ACKs
     * follow; rebuild with ACKs using the two-pass approach below. */
    if (ack_count > 0 && ack_ids) {
        offset -= 2; /* rewind the two closing braces */
        int n = snprintf(buf + offset, cap - (size_t)offset, ",\"ack_event_ids\":[");
        if (n < 0 || offset + n >= (int)cap) {
            free(buf);
            return -1;
        }
        offset += n;
        for (int i = 0; i < ack_count; i++) {
            n = snprintf(buf + offset, cap - (size_t)offset, "%s%d",
                         i > 0 ? "," : "", ack_ids[i]);
            if (n < 0 || offset + n >= (int)cap) {
                free(buf);
                return -1;
            }
            offset += n;
        }
        n = snprintf(buf + offset, cap - (size_t)offset, "]}}");
        if (n < 0 || offset + n >= (int)cap) {
            free(buf);
            return -1;
        }
        offset += n;
    }
    buf[offset] = '\0';
    *out = buf;
    return 0;
}

int fallback_build_pull_request(long pull_id, const int *ack_ids,
                                int ack_count, char **out) {
    if (!out) return -1;
    *out = NULL;

    static const char *const caps[] = { FALLBACK_CAPABILITIES };
    const int n_caps = (int)(sizeof(caps) / sizeof(caps[0]));

    size_t cap = 256 + (size_t)n_caps * 16 +
                 (ack_count > 0 ? (size_t)ack_count * 12 : 0);
    char *buf = malloc(cap);
    if (!buf) return -1;

    int offset = snprintf(buf, cap,
                          "{\"jsonrpc\":\"2.0\",\"id\":\"pull-%ld\","
                          "\"method\":\"%s\",\"params\":{\"capabilities\":[",
                          pull_id, AGENT_PULL);
    if (offset < 0 || (size_t)offset >= cap) {
        free(buf);
        return -1;
    }
    for (int i = 0; i < n_caps; i++) {
        int n = snprintf(buf + offset, cap - (size_t)offset, "%s\"%s\"",
                         i > 0 ? "," : "", caps[i]);
        if (n < 0 || offset + n >= (int)cap) {
            free(buf);
            return -1;
        }
        offset += n;
    }
    int n = snprintf(buf + offset, cap - (size_t)offset, "],\"ack_event_ids\":[");
    if (n < 0 || offset + n >= (int)cap) {
        free(buf);
        return -1;
    }
    offset += n;
    for (int i = 0; ack_ids && i < ack_count; i++) {
        n = snprintf(buf + offset, cap - (size_t)offset, "%s%d",
                     i > 0 ? "," : "", ack_ids[i]);
        if (n < 0 || offset + n >= (int)cap) {
            free(buf);
            return -1;
        }
        offset += n;
    }
    n = snprintf(buf + offset, cap - (size_t)offset, "]}}");
    if (n < 0 || offset + n >= (int)cap) {
        free(buf);
        return -1;
    }
    offset += n;
    buf[offset] = '\0';
    *out = buf;
    return 0;
}

int fallback_extract_events(const cJSON *response, const cJSON **events) {
    if (!response || !events) return -1;
    *events = NULL;

    const cJSON *result = cJSON_GetObjectItem(response, "result");
    if (!result || !cJSON_IsObject(result)) return -1;

    const cJSON *ev = cJSON_GetObjectItem(result, "events");
    if (ev && cJSON_IsArray(ev)) {
        *events = ev;
        return cJSON_GetArraySize(ev);
    }
    return 0;
}
