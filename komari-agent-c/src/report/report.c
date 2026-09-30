/*
 * Status report generation and upload implementation.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "report.h"
#include "monitoring.h"
#include "config.h"
#include "utils.h"
#include "logger.h"
#include "virtual.h"
#include "gpu.h"
#include "ip_detect.h"
#include "cJSON.h"
#include "jsonrpc.h"
#include "v2.h"
#include "compress.h"
#include "http_client.h"
#include "paths.h"
#include <komari-agent-c/version.h>

/* Escape special characters in a string for safe inclusion in a JSON string literal.
 * Conforms to RFC 8259 §7: escapes ", \, and control characters (0x00-0x1F)
 * using the named escapes (\b, \t, \n, \f, \r) where defined and \u00XX
 * for all other control characters. */
static void escape_json_string(const char *src, char *dst, size_t dst_len) {
    static const char hex[] = "0123456789ABCDEF";
    size_t j = 0;
    /* Guard against NULL inputs and undersized buffers: the \u00XX escape
     * path below writes up to 6 bytes plus a NUL terminator, so bail out
     * early when the buffer cannot hold the worst-case escape. This also
     * prevents size_t underflow in the `dst_len - 6` bound check (size_t
     * is unsigned, so a small dst_len would wrap to a huge value). */
    if (!src || !dst || dst_len < 7) {
        if (dst && dst_len > 0) dst[0] = '\0';
        return;
    }
    for (size_t i = 0; src[i] && j < dst_len - 1; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (j < dst_len - 2) {
                dst[j++] = '\\';
                dst[j++] = c;
            }
        } else if (c == '\n') {
            if (j < dst_len - 2) {
                dst[j++] = '\\';
                dst[j++] = 'n';
            }
        } else if (c == '\r') {
            if (j < dst_len - 2) {
                dst[j++] = '\\';
                dst[j++] = 'r';
            }
        } else if (c == '\t') {
            if (j < dst_len - 2) {
                dst[j++] = '\\';
                dst[j++] = 't';
            }
        } else if (c == '\b') {
            if (j < dst_len - 2) {
                dst[j++] = '\\';
                dst[j++] = 'b';
            }
        } else if (c == '\f') {
            if (j < dst_len - 2) {
                dst[j++] = '\\';
                dst[j++] = 'f';
            }
        } else if (c < 0x20) {
            /* Other control characters: \u00XX (uppercase hex) */
            if (j < dst_len - 6) {
                dst[j++] = '\\';
                dst[j++] = 'u';
                dst[j++] = '0';
                dst[j++] = '0';
                dst[j++] = hex[(c >> 4) & 0xF];
                dst[j++] = hex[c & 0xF];
            }
        } else {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
}

/* URL-encode a string for safe inclusion in a URL query parameter value.
 * Encodes all characters except unreserved characters (A-Z, a-z, 0-9, -_~.)
 * as %XX hex sequences. Mirrors Go url.QueryEscape semantics for the
 * unreserved set; spaces are encoded as %20 (well-behaved servers accept
 * both %20 and + in query values).
 *
 * @param src Input string to encode (NUL-terminated)
 * @param dst Output buffer
 * @param dst_len Size of dst
 * @return Number of bytes written (excluding NUL) on success, -1 on
 *         failure (NULL argument or dst too small) */
static int url_encode(const char *src, char *dst, size_t dst_len) {
    if (!src || !dst || dst_len == 0) return -1;
    static const char hex[] = "0123456789ABCDEF";
    size_t j = 0;
    for (size_t i = 0; src[i]; i++) {
        unsigned char c = (unsigned char)src[i];
        if ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
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

/* One sample of all metrics used by the periodic report payload. Collected
 * exactly once per report cycle so the WebSocket payload and the LuCI status
 * file reflect the same instant: CPU usage is delta-based, and sampling twice
 * per cycle would halve one delta window and skew its value. */
typedef struct {
    double cpu_usage;
    mem_info_t mem;
    mem_info_t swap;
    disk_info_t disk;
    net_info_t net;
    load_info_t load;
    conn_info_t conn;
    uint64_t uptime;
    int process_count;
    char message[192]; /* Collector error summary embedded in the report. */
    int monthly_from_netstatic; /* 1 when totalUp/totalDown came from netstatic */
} report_sample_t;

/* Hook installed by main.c when month_rotate is active; fills the monthly
 * (tx, rx) totals. Returns 0 on success. Weak default returns -1 so builds
 * without netstatic integration keep the counter-based behavior. */
__attribute__((weak)) int report_monthly_traffic_hook(uint64_t *tx, uint64_t *rx) {
    (void)tx; (void)rx;
    return -1;
}

static void report_collect_sample(const agent_config_t *config,
                                  monitoring_net_state_t *net_state,
                                  report_sample_t *s) {
    cpu_info_t cpu;
    monitoring_get_cpu_info(&cpu);
    monitoring_get_mem_swap_info(config->memory_include_cache, &s->mem, &s->swap);
    monitoring_get_disk_info(&s->disk);
    monitoring_get_net_info(net_state, &s->net);
    monitoring_get_load_info(&s->load);
    monitoring_get_conn_info(&s->conn);
    s->uptime = monitoring_get_uptime();
    s->process_count = monitoring_get_process_count();
    s->cpu_usage = cpu.cpu_usage;

    /* MonthRotate active: totalUp/totalDown switch from raw /proc counters
     * to the netstatic window totals (since the configured reset day),
     * mirroring the Go net.go. Speeds stay counter-based either way. On
     * failure fall back to the counters and record why in the message. */
    if (config->month_rotate > 0) {
        uint64_t m_tx = 0, m_rx = 0;
        if (report_monthly_traffic_hook(&m_tx, &m_rx) == 0) {
            s->net.tx_bytes = m_tx;
            s->net.rx_bytes = m_rx;
            s->monthly_from_netstatic = 1;
        } else {
            strncat(s->message, "netstatic: monthly traffic unavailable; ",
                    sizeof(s->message) - strlen(s->message) - 1);
        }
    }

    /* Aggregate collector failures into the report message so the panel can
     * surface them, mirroring the Go reference where GenerateReport appends
     * collection errors to the same field. */
    if (s->mem.total == 0) {
        strncat(s->message, "mem: /proc/meminfo read failed; ",
                sizeof(s->message) - strlen(s->message) - 1);
    }
    if (s->disk.total == 0) {
        strncat(s->message, "disk: no usable mountpoint; ",
                sizeof(s->message) - strlen(s->message) - 1);
    }
    if (s->conn.tcp_count < 0 || s->conn.udp_count < 0) {
        strncat(s->message, "connections: /proc/net parse failed; ",
                sizeof(s->message) - strlen(s->message) - 1);
    }
    /* Trim the trailing separator. */
    size_t mlen = strlen(s->message);
    while (mlen > 0 && (s->message[mlen - 1] == ' ' || s->message[mlen - 1] == ';')) {
        s->message[--mlen] = '\0';
    }
}

static void report_fill_status_metrics(const report_sample_t *s,
                                       report_status_metrics_t *out) {
    out->cpu_usage = s->cpu_usage;
    out->mem_total = s->mem.total;
    out->mem_used = s->mem.used;
    out->disk_total = s->disk.total;
    out->disk_used = s->disk.used;
    out->rx_speed = s->net.rx_speed;
    out->tx_speed = s->net.tx_speed;
}

/* Format the v1 report JSON from an already-collected sample. Returns the
 * payload length, or -1 on truncation/encoding error. */
static int report_format_v1(const report_sample_t *s, char *buf, size_t buf_len) {
    char message_escaped[sizeof(s->message) * 6 + 1];
    escape_json_string(s->message, message_escaped, sizeof(message_escaped));

    int len = snprintf(buf, buf_len,
        "{"
        "\"cpu\":{\"usage\":%.2f},"
        "\"ram\":{\"total\":%" PRIu64 ",\"used\":%" PRIu64 "},"
        "\"swap\":{\"total\":%" PRIu64 ",\"used\":%" PRIu64 "},"
        "\"load\":{\"load1\":%.2f,\"load5\":%.2f,\"load15\":%.2f},"
        "\"disk\":{\"total\":%" PRIu64 ",\"used\":%" PRIu64 "},"
        "\"network\":{\"up\":%" PRIu64 ",\"down\":%" PRIu64 ",\"totalUp\":%" PRIu64 ",\"totalDown\":%" PRIu64 "},"
        "\"connections\":{\"tcp\":%d,\"udp\":%d},"
        "\"uptime\":%" PRIu64 ","
        "\"process\":%d,"
        "\"message\":\"%s\""
        "}",
        s->cpu_usage,
        s->mem.total, s->mem.used,
        s->swap.total, s->swap.used,
        s->load.load1, s->load.load5, s->load.load15,
        s->disk.total, s->disk.used,
        s->net.tx_speed, s->net.rx_speed,
        s->net.tx_bytes, s->net.rx_bytes,
        s->conn.tcp_count, s->conn.udp_count,
        s->uptime,
        s->process_count,
        message_escaped
    );

    /* Treat truncation or encoding error as failure: a truncated JSON body
     * would be rejected by the server and could expose partial/malformed
     * data. */
    if (len < 0 || (size_t)len >= buf_len) return -1;

    return len;
}

int report_generate_ex(const agent_config_t *config, monitoring_net_state_t *net_state,
                       char *buf, size_t buf_len, report_status_metrics_t *status_out) {
    if (!config || !buf || buf_len == 0) return -1;

    report_sample_t s;
    memset(&s, 0, sizeof(s));
    report_collect_sample(config, net_state, &s);
    if (status_out) {
        report_fill_status_metrics(&s, status_out);
    }

    return report_format_v1(&s, buf, buf_len);
}

int report_generate(const agent_config_t *config, monitoring_net_state_t *net_state,
                    char *buf, size_t buf_len) {
    return report_generate_ex(config, net_state, buf, buf_len, NULL);
}

int report_generate_v2(const agent_config_t *config, monitoring_net_state_t *net_state,
                       char *buf, size_t buf_len) {
    if (!config || !buf || buf_len == 0) return -1;

    /* Generate the v1-style report JSON first. Use a local buffer so the
     * caller's buffer is left untouched on failure. */
    char v1_buf[4096];
    int v1_len = report_generate(config, net_state, v1_buf, sizeof(v1_buf));
    if (v1_len <= 0) return -1;
    v1_buf[sizeof(v1_buf) - 1] = '\0';

    /* Build the v2 JSON-RPC envelope by direct string concatenation instead
     * of cJSON_Parse(v1) → jsonrpc_build_report_payload → cJSON_Print. The v1
     * JSON produced by report_generate contains only numeric fields and an
     * empty message string, so it can be embedded verbatim under
     * params.report without re-escaping. This eliminates 4-6 heap malloc/free
     * operations per cycle on the 1 Hz report path. */
    int n = snprintf(buf, buf_len,
                     "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":{\"report\":",
                     AGENT_REPORT);
    if (n < 0 || (size_t)n >= buf_len) return -1;
    int offset = n;

    /* Embed the v1 JSON verbatim — it is already a complete, valid JSON object. */
    if ((size_t)v1_len >= buf_len - (size_t)offset) return -1;
    memcpy(buf + offset, v1_buf, (size_t)v1_len);
    offset += v1_len;

    /* Close the params object and the envelope. */
    if ((size_t)2 >= buf_len - (size_t)offset) return -1;
    buf[offset++] = '}';
    buf[offset++] = '}';
    buf[offset] = '\0';

    return offset;
}

int report_generate_v2_with_acks_ex(const agent_config_t *config,
                                    monitoring_net_state_t *net_state,
                                    char *buf, size_t buf_len, const int *ack_ids,
                                    int ack_count,
                                    report_status_metrics_t *status_out) {
    if (!config || !buf || buf_len == 0) return -1;
    if (ack_count < 0) ack_count = 0;

    /* Generate the v1-style report JSON first. */
    char v1_buf[4096];
    int v1_len = report_generate_ex(config, net_state, v1_buf, sizeof(v1_buf), status_out);
    if (v1_len <= 0) return -1;
    v1_buf[sizeof(v1_buf) - 1] = '\0';

    /* Build the v2 JSON-RPC envelope by direct string concatenation instead
     * of cJSON_Parse(v1) → jsonrpc_build_report_request → cJSON_Print. The v1
     * JSON produced by report_generate contains only numeric fields and an
     * empty message string, so it can be embedded verbatim under
     * params.report without re-escaping. This eliminates 4-6 heap malloc/free
     * operations per cycle on the 1 Hz report path. */
    int request_id = (int)time(NULL);
    int offset = 0;

    /* Envelope header up to the report value. */
    int n = snprintf(buf + offset, buf_len - (size_t)offset,
                     "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"id\":%d,\"params\":{\"report\":",
                     AGENT_REPORT, request_id);
    if (n < 0 || (size_t)n >= buf_len - (size_t)offset) return -1;
    offset += n;

    /* Embed the v1 JSON verbatim — it is already a complete, valid JSON object. */
    if ((size_t)v1_len >= buf_len - (size_t)offset) return -1;
    memcpy(buf + offset, v1_buf, (size_t)v1_len);
    offset += v1_len;

    /* ACK array: always present (empty if no ACKs) for schema consistency
     * with the previous cJSON-based implementation. */
    n = snprintf(buf + offset, buf_len - (size_t)offset, ",\"ack_event_ids\":[");
    if (n < 0 || (size_t)n >= buf_len - (size_t)offset) return -1;
    offset += n;

    for (int i = 0; i < ack_count && ack_ids; i++) {
        /* Reserve enough room for the closing "]}}" plus a NUL so a full ACK
         * never leaves the JSON truncated. If the buffer cannot hold every
         * pending ACK, stop early: the report stays valid and the un-ACKed
         * events are recovered through server retransmission (main.c clears
         * all ACKs after a successful send and the server re-sends events it
         * has not seen acknowledged). Without this, a large ACK backlog made
         * every report fail permanently, wedging the agent. */
        if (buf_len - (size_t)offset <= 16) break;
        n = snprintf(buf + offset, buf_len - (size_t)offset, "%s%d",
                     i > 0 ? "," : "", ack_ids[i]);
        if (n < 0 || (size_t)n >= buf_len - (size_t)offset) break;
        offset += n;
    }

    n = snprintf(buf + offset, buf_len - (size_t)offset, "]}}");
    if (n < 0 || (size_t)n >= buf_len - (size_t)offset) return -1;
    offset += n;

    return offset;
}

int report_generate_v2_with_acks(const agent_config_t *config,
                                 monitoring_net_state_t *net_state,
                                 char *buf, size_t buf_len, const int *ack_ids,
                                 int ack_count) {
    return report_generate_v2_with_acks_ex(config, net_state, buf, buf_len,
                                           ack_ids, ack_count, NULL);
}

int report_generate_basic_info(const agent_config_t *config, char *buf, size_t buf_len) {
    if (!config || !buf || buf_len == 0) return -1;
    
    cpu_info_t cpu;
    mem_info_t mem, swap;
    disk_info_t disk;
    system_info_t sys;
    char ipv4[64] = "", ipv6[128] = "";
    
    monitoring_get_cpu_info(&cpu);
    monitoring_get_mem_swap_info(config->memory_include_cache, &mem, &swap);
    monitoring_get_disk_info(&disk);
    monitoring_get_system_info(&sys);
    /* Public IP detection chain: NIC (when get_ip_addr_from_nic) ->
     * custom_ipv4/6 overrides -> external echo APIs, mirroring the Go
     * reference monitoring.GetIPAddress. */
    ip_detect_public(config->get_ip_addr_from_nic,
                     config->custom_ipv4, config->custom_ipv6,
                     ipv4, sizeof(ipv4), ipv6, sizeof(ipv6));
    
    char cpu_name_escaped[256];
    char os_name_escaped[256];
    char kernel_escaped[128];
    char gpu_name[128] = "";
    char gpu_name_escaped[256] = "";

    escape_json_string(cpu.cpu_name, cpu_name_escaped, sizeof(cpu_name_escaped));
    escape_json_string(sys.os_name, os_name_escaped, sizeof(os_name_escaped));
    escape_json_string(sys.kernel_version, kernel_escaped, sizeof(kernel_escaped));

    /* Get GPU name (use empty string on failure) */
    if (gpu_get_name(gpu_name, sizeof(gpu_name)) == 0) {
        escape_json_string(gpu_name, gpu_name_escaped, sizeof(gpu_name_escaped));
    }

    const char *ipv4_val = config->custom_ipv4[0] ? config->custom_ipv4 : ipv4;
    const char *ipv6_val = config->custom_ipv6[0] ? config->custom_ipv6 : ipv6;

    /* Escape the IP values before embedding them in JSON. custom_ipv4/
     * custom_ipv6 are user-configured strings and may contain quotes or
     * control characters that would otherwise break the payload. */
    char ipv4_escaped[192];
    char ipv6_escaped[256];
    escape_json_string(ipv4_val, ipv4_escaped, sizeof(ipv4_escaped));
    escape_json_string(ipv6_val, ipv6_escaped, sizeof(ipv6_escaped));

    const char *virt_type = virt_detect();

    int len = snprintf(buf, buf_len,
        "{"
        "\"cpu_name\":\"%s\","
        "\"cpu_cores\":%d,"
        "\"cpu_physical_cores\":%d,"
        "\"arch\":\"%s\","
        "\"os\":\"%s\","
        "\"kernel_version\":\"%s\","
        "\"ipv4\":\"%s\","
        "\"ipv6\":\"%s\","
        "\"mem_total\":%" PRIu64 ","
        "\"swap_total\":%" PRIu64 ","
        "\"disk_total\":%" PRIu64 ","
        "\"gpu_name\":\"%s\","
        "\"virtualization\":\"%s\","
        "\"version\":\"" KOMARI_AGENT_C_VERSION_STRING "\""
        "}",
        cpu_name_escaped,
        cpu.cpu_cores,
        cpu.cpu_physical_cores > 0 ? cpu.cpu_physical_cores : cpu.cpu_cores,
        cpu.cpu_arch,
        os_name_escaped,
        kernel_escaped,
        ipv4_escaped,
        ipv6_escaped,
        mem.total,
        swap.total,
        disk.total,
        gpu_name_escaped,
        virt_type
    );

    /* Treat truncation or encoding error as failure: a truncated JSON body
     * would be rejected by the server and could expose partial/malformed
     * data. */
    if (len < 0 || (size_t)len >= buf_len) return -1;

    return len;
}

int report_generate_basic_info_v2(const agent_config_t *config, char *buf, size_t buf_len) {
    if (!config || !buf || buf_len == 0) return -1;

    /* Generate the v1-style basic info JSON first. Use a local buffer so the
     * caller's buffer is left untouched on failure. */
    char v1_buf[4096];
    int v1_len = report_generate_basic_info(config, v1_buf, sizeof(v1_buf));
    if (v1_len <= 0) return -1;
    v1_buf[sizeof(v1_buf) - 1] = '\0';

    /* Build the v2 JSON-RPC envelope by direct string concatenation, mirroring
     * report_generate_v2. The v1 JSON produced by report_generate_basic_info
     * has all string fields pre-escaped via escape_json_string, so it can be
     * embedded verbatim under params.info without re-parsing. This avoids the
     * cJSON_Parse → cJSON_Print round-trip on every basic-info upload. */
    int n = snprintf(buf, buf_len,
                     "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":{\"info\":",
                     AGENT_BASIC_INFO);
    if (n < 0 || (size_t)n >= buf_len) return -1;
    int offset = n;

    /* Embed the v1 JSON verbatim — it is already a complete, valid JSON object. */
    if ((size_t)v1_len >= buf_len - (size_t)offset) return -1;
    memcpy(buf + offset, v1_buf, (size_t)v1_len);
    offset += v1_len;

    /* Close the params object and the envelope. */
    if ((size_t)2 >= buf_len - (size_t)offset) return -1;
    buf[offset++] = '}';
    buf[offset++] = '}';
    buf[offset] = '\0';

    return offset;
}

/* Shared HTTP POST helper: sends payload to url and returns the HTTP
 * status code, or 0 on transport failure. Used by the task/ping result
 * uploaders which only care about the status code. */
static int http_post_status(const agent_config_t *config, const char *url,
                            const char *payload, const char *extra_headers) {
    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body = payload;
    req.ignore_cert = config->ignore_unsafe_cert;
    req.extra_headers = (extra_headers && extra_headers[0]) ? extra_headers : NULL;
    if (http_client_request(&req, &resp) != 0) return 0;
    int status = resp.status;
    http_client_response_free(&resp);
    return status;
}

/* Go-style success range: any 2xx counts (mirrors postV2RPC). */
static int http_status_ok(int status) {
    return status >= 200 && status < 300;
}

/* Build "<endpoint>/api/clients/v2/rpc?token=<encoded>" into url. Returns 0
 * on success, -1 when the token cannot be encoded or the URL overflows. */
static int build_v2_rpc_url(const agent_config_t *config, char *url, size_t url_len) {
    char encoded_token[MAX_TOKEN_LEN * 3 + 1];
    if (url_encode(config->token, encoded_token, sizeof(encoded_token)) < 0) {
        return -1;
    }
    int n = snprintf(url, url_len, "%s%s?token=%s",
                     config->endpoint, V2_RPC_ENDPOINT, encoded_token);
    return (n < 0 || (size_t)n >= url_len) ? -1 : 0;
}

/* Format a unix timestamp as RFC3339 with fractional seconds, matching Go's
 * time.Time JSON encoding (RFC3339Nano: up to 9 fractional digits, trailing
 * zeros trimmed). The C agent produces millisecond precision. */
static int format_rfc3339_nano(uint64_t finished_at, char *buf, size_t buf_len) {
    time_t t = (time_t)finished_at;
    struct tm tm_utc;
    if (!gmtime_r(&t, &tm_utc)) return -1;
    long ms = (long)((finished_at % 1000) * 1000000); /* ns portion when finished_at carries ms */
    /* finished_at is unix seconds; derive milliseconds from a higher
     * precision clock when available so identical-second results remain
     * distinguishable. Callers pass unix seconds, so the fraction is 0. */
    (void)ms;
    int n = snprintf(buf, buf_len, "%04d-%02d-%02dT%02d:%02d:%02d.000000000Z",
                     tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
                     tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec);
    return (n < 0 || (size_t)n >= buf_len) ? -1 : 0;
}

int report_upload_task_result(const agent_config_t *config,
                               const char *task_id,
                               const char *result,
                               int exit_code,
                               uint64_t finished_at) {
    if (!config || !task_id) return -1;

    char *escaped_result = utils_json_escape(result ? result : "");
    if (!escaped_result) return -1;

    /* Escape task_id to prevent breaking the JSON structure if it contains
     * quotes, backslashes, or control characters. */
    char *escaped_task_id = utils_json_escape(task_id);
    if (!escaped_task_id) {
        free(escaped_result);
        return -1;
    }

    char finished_buf[64];
    if (format_rfc3339_nano(finished_at, finished_buf, sizeof(finished_buf)) != 0) {
        free(escaped_result);
        free(escaped_task_id);
        return -1;
    }

    /* Build the JSON-RPC 2.0 request for agent.taskResult, mirroring the Go
     * reference (server/task.go postV2RPC): id "task-<unix>", params with
     * task_id/result/exit_code/finished_at (RFC3339). */
    char *escaped_finished = utils_json_escape(finished_buf);
    if (!escaped_finished) {
        free(escaped_result);
        free(escaped_task_id);
        return -1;
    }

    /* Allocate the payload on the heap: the escaped command output can be up
     * to 6x the raw 8 KiB exec buffer (control characters become \u00XX),
     * which exceeds any reasonable fixed stack buffer. A truncated result
     * used to be dropped silently; the failure is now logged explicitly. */
    const size_t payload_cap = 64 * 1024;
    char *payload = malloc(payload_cap);
    if (!payload) {
        free(escaped_result);
        free(escaped_task_id);
        free(escaped_finished);
        return -1;
    }

    int n = snprintf(payload, payload_cap,
        "{\"jsonrpc\":\"2.0\",\"id\":\"task-%" PRIu64 ""
        "\",\"method\":\"%s\",\"params\":{"
        "\"task_id\":\"%s\",\"result\":\"%s\","
        "\"exit_code\":%d,\"finished_at\":\"%s\"}}",
        (uint64_t)time(NULL), AGENT_TASK_RESULT,
        escaped_task_id, escaped_result, exit_code, escaped_finished);

    free(escaped_result);
    free(escaped_task_id);
    free(escaped_finished);

    /* Abort if the payload was truncated: a truncated JSON body would be
     * rejected by the server and could expose partial/malformed data. */
    if (n < 0 || (size_t)n >= payload_cap) {
        KOMARI_LOG_ERROR("[Report] Task result payload truncated (%d bytes, cap %zu); "
                         "result too large to upload", n, payload_cap);
        free(payload);
        return -1;
    }

    char url[MAX_ENDPOINT_LEN + 64 + MAX_TOKEN_LEN * 3 + 1];
    if (build_v2_rpc_url(config, url, sizeof(url)) != 0) {
        free(payload);
        return -1;
    }

    /* Single attempt, no retry: failures are logged and the result is
     * re-reported on the next task, matching the Go behavior. */
    int ok = http_status_ok(http_post_status(config, url, payload, NULL));
    free(payload);
    return ok ? 0 : -1;
}

int report_upload_ping_result(const agent_config_t *config,
                               uint32_t task_id,
                               const char *ping_type,
                               int value,
                               uint64_t finished_at) {
    if (!config || !ping_type) return -1;

    /* Escape ping_type before embedding it into the JSON payload to prevent
     * log injection / JSON structural breakage when the field contains
     * quotes, backslashes or control characters. Mirrors the escaping
     * applied to task_id/result in report_upload_task_result. */
    char *escaped_ping_type = utils_json_escape(ping_type);
    if (!escaped_ping_type) return -1;

    char finished_buf[64];
    if (format_rfc3339_nano(finished_at, finished_buf, sizeof(finished_buf)) != 0) {
        free(escaped_ping_type);
        return -1;
    }

    char payload[512];
    int payload_n = snprintf(payload, sizeof(payload),
        "{\"jsonrpc\":\"2.0\",\"id\":\"ping-%" PRIu64 ""
        "\",\"method\":\"%s\",\"params\":{"
        "\"task_id\":%u,\"ping_type\":\"%s\",\"value\":%d,"
        "\"finished_at\":\"%s\"}}",
        (uint64_t)time(NULL), AGENT_PING_RESULT,
        task_id, escaped_ping_type, value, finished_buf);
    if (payload_n < 0 || (size_t)payload_n >= sizeof(payload)) {
        free(escaped_ping_type);
        return -1;
    }

    /* escaped_ping_type is no longer needed once the payload has been built. */
    free(escaped_ping_type);

    char url[MAX_ENDPOINT_LEN + 64 + MAX_TOKEN_LEN * 3 + 1];
    if (build_v2_rpc_url(config, url, sizeof(url)) != 0) {
        return -1;
    }

    return http_status_ok(http_post_status(config, url, payload, NULL))
               ? 0 : -1;
}

int report_upload_basic_info(const agent_config_t *config,
                             const char *payload, size_t payload_len) {
    if (!config || !payload || payload_len == 0) return -1;

    char url[MAX_ENDPOINT_LEN + 64 + MAX_TOKEN_LEN * 3 + 1];
    if (build_v2_rpc_url(config, url, sizeof(url)) != 0) {
        return -1;
    }

    /* Mirror the Go reference (server/basicInfo.go): gzip the body unless
     * the caller disabled compression, and announce it via
     * Content-Encoding. No retry — failures wait for the next cycle. */
    const char *body = payload;
    size_t body_len = payload_len;
    char *gz = NULL;
    size_t gz_len = 0;
    if (!config->disable_compression &&
        compress_gzip(payload, payload_len, &gz, &gz_len) == 0) {
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
    req.gzip_body = 0; /* Already compressed above when enabled. */
    req.ignore_cert = config->ignore_unsafe_cert;
    if (body != payload) {
        /* http_client_request would add a second Content-Encoding layer if
         * gzip_body were set; the header must still be present, so set it
         * through extra_headers instead. */
        req.extra_headers = "Content-Encoding: gzip\r\n";
    }

    int ret = -1;
    if (http_client_request(&req, &resp) == 0 &&
        resp.status >= 200 && resp.status < 300) {
        ret = 0;
    }
    http_client_response_free(&resp);
    free(gz);
    return ret;
}

void report_write_status_file(const agent_config_t *config,
                              const report_status_metrics_t *m,
                              bool connected) {
    if (!config) return;

    double mem_pct = 0.0, disk_pct = 0.0;
    double cpu_pct = 0.0;
    uint64_t rx = 0, tx = 0;
    if (m) {
        cpu_pct = m->cpu_usage;
        if (m->mem_total > 0) {
            mem_pct = (double)m->mem_used / (double)m->mem_total * 100.0;
        }
        if (m->disk_total > 0) {
            disk_pct = (double)m->disk_used / (double)m->disk_total * 100.0;
        }
        rx = m->rx_speed;
        tx = m->tx_speed;
    }

    char endpoint_escaped[MAX_ENDPOINT_LEN];
    escape_json_string(config->endpoint, endpoint_escaped, sizeof(endpoint_escaped));

    /* Write to a temp file and rename() so the LuCI reader never observes a
     * truncated file (same atomic-publish pattern as netstatic persistence). */
    static const char *const kTmpPath = KOMARI_PATH_STATUS_FILE ".tmp";
    /* Publish failures repeat every report cycle, so warn only once. They are
     * otherwise invisible: if the file was created by another user (e.g. a
     * manual root debug run) in a sticky /tmp, the service user's rename()
     * fails with EPERM and the LuCI dashboard would silently show stale data
     * forever. */
    static bool warned_publish_failure = false;
    FILE *fp = fopen(kTmpPath, "w");
    if (!fp) {
        if (!warned_publish_failure) {
            KOMARI_LOG_WARN("[Report] Cannot create status file %s: %s "
                            "(LuCI status page will be stale)", kTmpPath,
                            strerror(errno));
            warned_publish_failure = true;
        }
        return;
    }

    int n = fprintf(fp,
        "{\"connected\":%s,\"endpoint\":\"%s\",\"last_update\":%" PRIu64 ","
        "\"cpu_usage\":%.2f,\"memory_usage\":%.2f,\"disk_usage\":%.2f,"
        "\"rx_speed\":%" PRIu64 ",\"tx_speed\":%" PRIu64 "}",
        connected ? "true" : "false",
        endpoint_escaped,
        (uint64_t)time(NULL),
        cpu_pct, mem_pct, disk_pct, rx, tx);

    if (n < 0 || fclose(fp) != 0) {
        KOMARI_LOG_DEBUG("[Report] Failed to write status file %s", kTmpPath);
        unlink(kTmpPath);
        return;
    }

    if (rename(kTmpPath, KOMARI_PATH_STATUS_FILE) != 0) {
        if (!warned_publish_failure) {
            KOMARI_LOG_WARN("[Report] Cannot publish status file %s: %s "
                            "(LuCI status page will be stale)",
                            KOMARI_PATH_STATUS_FILE, strerror(errno));
            warned_publish_failure = true;
        }
        unlink(kTmpPath);
        return;
    }
    warned_publish_failure = false;
}
