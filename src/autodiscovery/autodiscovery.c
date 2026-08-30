/*
 * Auto-discovery implementation: HTTP registration, config persistence
 * and reuse logic for the Komari agent.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "autodiscovery.h"
#include "utils.h"
#include "logger.h"
#include "cJSON.h"
#include "http_client.h"

/* HTTP response buffer size */
#define HTTP_RESPONSE_BUF_SIZE 8192

/* Maximum length of each part after URL parsing */
#define URL_SCHEME_LEN  16
#define URL_HOST_LEN    256
#define URL_PATH_LEN    768

/* Connect/send/recv timeout for HTTP requests (MIN-34: extracted magic number). */
#define HTTP_CONNECT_TIMEOUT_SEC 10

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

int autodiscovery_get_file_path(char *path, size_t path_len) {
    if (!path || path_len == 0) return -1;

    const char *src = AUTODISCOVERY_FILE_PATH;
    if (strlen(src) >= path_len) return -1;

    strncpy(path, src, path_len - 1);
    path[path_len - 1] = '\0';
    return 0;
}

int autodiscovery_load_config(autodiscovery_config_t *config) {
    if (!config) return -1;

    memset(config, 0, sizeof(*config));

    char path[256];
    if (autodiscovery_get_file_path(path, sizeof(path)) != 0) {
        return -1;
    }

    if (!utils_file_exists(path)) {
        return -1;
    }

    char *buf = malloc(4096);
    if (!buf) {
        KOMARI_LOG_ERROR("Auto-discovery: Failed to allocate read buffer");
        return -1;
    }

    if (utils_read_file_string(path, buf, 4096) != 0) {
        free(buf);
        KOMARI_LOG_ERROR("Auto-discovery: Failed to read configuration file path=%s", path);
        return -1;
    }

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        KOMARI_LOG_ERROR("Auto-discovery: Failed to parse configuration JSON");
        return -1;
    }

    cJSON *uuid_item = cJSON_GetObjectItem(root, "uuid");
    cJSON *token_item = cJSON_GetObjectItem(root, "token");

    int ret = 0;
    if (uuid_item && cJSON_IsString(uuid_item) && uuid_item->valuestring) {
        strncpy(config->uuid, uuid_item->valuestring, sizeof(config->uuid) - 1);
        config->uuid[sizeof(config->uuid) - 1] = '\0';
    } else {
        ret = -1;
    }

    if (token_item && cJSON_IsString(token_item) && token_item->valuestring) {
        strncpy(config->token, token_item->valuestring, sizeof(config->token) - 1);
        config->token[sizeof(config->token) - 1] = '\0';
    } else {
        ret = -1;
    }

    cJSON_Delete(root);

    if (ret != 0) {
        KOMARI_LOG_WARN("Auto-discovery: Configuration file missing uuid or token field");
    }

    return ret;
}

int autodiscovery_save_config(const autodiscovery_config_t *config) {
    if (!config) return -1;

    char path[256];
    if (autodiscovery_get_file_path(path, sizeof(path)) != 0) {
        return -1;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        KOMARI_LOG_ERROR("Auto-discovery: Failed to create JSON object");
        return -1;
    }

    if (!cJSON_AddStringToObject(root, "uuid", config->uuid) ||
        !cJSON_AddStringToObject(root, "token", config->token)) {
        cJSON_Delete(root);
        KOMARI_LOG_ERROR("Auto-discovery: Failed to add JSON field");
        return -1;
    }

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) {
        KOMARI_LOG_ERROR("Auto-discovery: Failed to serialize JSON");
        return -1;
    }

    /* Persist with restrictive permissions: the file contains the agent token */
    int ret = utils_write_file_string(path, json_str, 0600);
    cJSON_free(json_str);

    if (ret != 0) {
        KOMARI_LOG_ERROR("Auto-discovery: Failed to write configuration file path=%s", path);
        return -1;
    }

    KOMARI_LOG_DEBUG("Auto-discovery: Configuration saved path=%s", path);
    return 0;
}

/* Check whether a string contains CR or LF characters (header injection prevention). */
static int contains_crlf(const char *s) {
    if (!s) return 0;
    for (; *s; s++) {
        if (*s == '\r' || *s == '\n') return 1;
    }
    return 0;
}

int autodiscovery_register(const char *endpoint,
                            const char *auto_discovery_key,
                            const char *hostname,
                            autodiscovery_config_t *config) {
    if (!endpoint || !auto_discovery_key || !hostname || !config) return -1;

    /* Prevent HTTP header injection: reject CR/LF in user-controlled fields */
    if (contains_crlf(auto_discovery_key)) {
        KOMARI_LOG_ERROR("Auto-discovery: auto_discovery_key contains CR/LF characters");
        return -1;
    }
    if (contains_crlf(hostname)) {
        KOMARI_LOG_ERROR("Auto-discovery: hostname contains CR/LF characters");
        return -1;
    }

    /* Enforce HTTPS for the registration endpoint. The auto_discovery_key
     * is sent in an Authorization: Bearer header; transmitting it over plain
     * HTTP would expose the credential to network sniffing. Reject non-HTTPS
     * endpoints before constructing the request. */
    if (strncmp(endpoint, "https://", 8) != 0) {
        KOMARI_LOG_ERROR("Auto-discovery: endpoint must use HTTPS to protect the registration key");
        return -1;
    }

    /*
     * Design note: Unlike the authenticated endpoints (which pass the agent
     * token via URL query string, see websocket.c and report.c), the
     * registration endpoint uses the Authorization: Bearer header with the
     * auto-discovery key. This is intentional and matches the Go reference
     * implementation (see .komari-agent-main/cmd/autodiscovery.go): the
     * registration endpoint is a bootstrap path that issues a new agent
     * token, so the agent does not yet have a token to put in the query
     * string. The "?name=" query parameter carries the hostname, not
     * authentication material.
     */
    /* URL-encode the hostname for the ?name= query parameter to handle any
     * special characters safely (mirrors Go url.QueryEscape). Hostnames
     * normally only contain unreserved characters, but encoding is applied
     * as defense in depth. The encoded form may be up to 3x the original. */
    char encoded_name[256 * 3 + 1];
    if (url_encode(hostname, encoded_name, sizeof(encoded_name)) < 0) {
        KOMARI_LOG_ERROR("Auto-discovery: Hostname URL encoding failed");
        return -1;
    }

    /* Build registration URL: {endpoint}/api/clients/register?name={hostname} */
    char url[768 + 256 * 3 + 1];
    int n = snprintf(url, sizeof(url), "%s/api/clients/register?name=%s",
                     endpoint, encoded_name);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        KOMARI_LOG_ERROR("Auto-discovery: Registration URL too long");
        return -1;
    }

    /* Build Authorization header */
    char auth_header[512];
    n = snprintf(auth_header, sizeof(auth_header),
                 "Authorization: Bearer %s\r\n", auto_discovery_key);
    if (n < 0 || (size_t)n >= sizeof(auth_header)) {
        KOMARI_LOG_ERROR("Auto-discovery: Authorization header too long");
        return -1;
    }

    /* Send POST request (empty body) via the shared HTTP client */
    char response[HTTP_RESPONSE_BUF_SIZE];
    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body = "";
    req.extra_headers = auth_header;
    req.response_buf = response;
    req.response_len = sizeof(response);
    if (http_client_request(&req, &resp) != 0 ||
        resp.status < 200 || resp.status >= 300) {
        KOMARI_LOG_ERROR("Auto-discovery: Registration request failed url=%s", url);
        http_client_response_free(&resp);
        return -1;
    }
    http_client_response_free(&resp);

    /* Parse response JSON, extract uuid and token */
    cJSON *root = cJSON_Parse(response);
    if (!root) {
        KOMARI_LOG_ERROR("Auto-discovery: Failed to parse response JSON");
        return -1;
    }

    memset(config, 0, sizeof(*config));

    cJSON *uuid_item = cJSON_GetObjectItem(root, "uuid");
    cJSON *token_item = cJSON_GetObjectItem(root, "token");

    int ret = 0;
    if (uuid_item && cJSON_IsString(uuid_item) && uuid_item->valuestring) {
        strncpy(config->uuid, uuid_item->valuestring, sizeof(config->uuid) - 1);
        config->uuid[sizeof(config->uuid) - 1] = '\0';
    } else {
        ret = -1;
    }

    if (token_item && cJSON_IsString(token_item) && token_item->valuestring) {
        strncpy(config->token, token_item->valuestring, sizeof(config->token) - 1);
        config->token[sizeof(config->token) - 1] = '\0';
    } else {
        ret = -1;
    }

    cJSON_Delete(root);

    if (ret != 0) {
        KOMARI_LOG_ERROR("Auto-discovery: Response missing uuid or token field");
        return -1;
    }

    /* Save to configuration file */
    if (autodiscovery_save_config(config) != 0) {
        /* Save failure does not affect in-memory configuration */
        KOMARI_LOG_WARN("Auto-discovery: Failed to save configuration file, using in-memory configuration only");
    }

    KOMARI_LOG_INFO("Auto-discovery: Registration succeeded uuid=%s", config->uuid);
    return 0;
}

int autodiscovery_handle(const char *endpoint,
                          const char *auto_discovery_key,
                          char *token,
                          size_t token_len) {
    if (!endpoint || !auto_discovery_key || !token || token_len == 0) return -1;

    token[0] = '\0';

    /* 1. Try to load existing configuration */
    autodiscovery_config_t config;
    if (autodiscovery_load_config(&config) == 0 && config.token[0] != '\0') {
        /* 2. Configuration exists and token is not empty, reuse directly */
        if (strlen(config.token) >= token_len) {
            KOMARI_LOG_ERROR("Auto-discovery: Token buffer too small");
            return -1;
        }
        strncpy(token, config.token, token_len - 1);
        token[token_len - 1] = '\0';
        KOMARI_LOG_INFO("Auto-discovery: Reusing saved configuration uuid=%s", config.uuid);
        return 0;
    }

    /* 3. Configuration does not exist or token is empty, initiate registration */
    char hostname[256];
    if (utils_get_hostname(hostname, sizeof(hostname)) != 0) {
        KOMARI_LOG_ERROR("Auto-discovery: Failed to get hostname");
        return -1;
    }

    if (autodiscovery_register(endpoint, auto_discovery_key, hostname, &config) != 0) {
        KOMARI_LOG_ERROR("Auto-discovery: Failed to register to panel");
        return -1;
    }

    if (strlen(config.token) >= token_len) {
        KOMARI_LOG_ERROR("Auto-discovery: Token buffer too small");
        return -1;
    }
    strncpy(token, config.token, token_len - 1);
    token[token_len - 1] = '\0';

    return 0;
}
