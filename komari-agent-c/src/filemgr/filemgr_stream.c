/*
 * File manager streaming ops implementation, mirroring server/file_stream.go
 * and the transfer-related parts of files.go.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#define _GNU_SOURCE

#include "filemgr_stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "logger.h"
#include "http_client.h"
#include "filemgr.h"

/* Per-transfer HTTP timeout (Go: 30 minutes). */
#define TRANSFER_HTTP_TIMEOUT_SEC (30 * 60)

/* Validate a panel-supplied transfer identifier (transfer_id, transfer_token,
 * upload_id): these flow into HTTP request headers, the URL path and local
 * part-file names, so CR/LF (header injection) and path separators (part-file
 * path escape) must be rejected. Mirrors the CRLF guards the codebase applies
 * to terminal_id/ping_target. */
static bool transfer_id_valid(const char *s) {
    if (!s || !s[0]) return false;
    if (strlen(s) > 128) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (c < 0x20 || c == 0x7F) return false;       /* control chars, CR/LF */
        if (c == '/' || c == '\\') return false;       /* path separators */
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* args helpers                                                        */
/* ------------------------------------------------------------------ */

static const char *args_str(const cJSON *args, const char *key) {
    cJSON *it = cJSON_GetObjectItem(args, key);
    return (it && cJSON_IsString(it) && it->valuestring) ? it->valuestring : NULL;
}

static long long args_ll(const cJSON *args, const char *key, long long def) {
    cJSON *it = cJSON_GetObjectItem(args, key);
    return (it && cJSON_IsNumber(it)) ? (long long)it->valuedouble : def;
}

static bool args_bool(const cJSON *args, const char *key) {
    cJSON *it = cJSON_GetObjectItem(args, key);
    return it && cJSON_IsTrue(it);
}

/* Build "<endpoint>/api/clients/transfer/<id>?token=<enc>&transfer_token=<enc>". */
static int build_transfer_url(const agent_config_t *config, const char *transfer_id,
                              const char *transfer_token, char *url, size_t url_len) {
    static const char hex[] = "0123456789ABCDEF";

    char enc_tok[MAX_TOKEN_LEN * 3 + 1];
    size_t j = 0;
    for (const char *p = config->token; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            if (j + 1 >= sizeof(enc_tok)) return -1;
            enc_tok[j++] = (char)c;
        } else {
            if (j + 3 >= sizeof(enc_tok)) return -1;
            enc_tok[j++] = '%';
            enc_tok[j++] = hex[(c >> 4) & 0xF];
            enc_tok[j++] = hex[c & 0xF];
        }
    }
    enc_tok[j] = '\0';

    char enc_tt[512];
    j = 0;
    for (const char *p = transfer_token; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            if (j + 1 >= sizeof(enc_tt)) return -1;
            enc_tt[j++] = (char)c;
        } else {
            if (j + 3 >= sizeof(enc_tt)) return -1;
            enc_tt[j++] = '%';
            enc_tt[j++] = hex[(c >> 4) & 0xF];
            enc_tt[j++] = hex[c & 0xF];
        }
    }
    enc_tt[j] = '\0';

    int n = snprintf(url, url_len,
                     "%s/api/clients/transfer/%s?token=%s&transfer_token=%s",
                     config->endpoint, transfer_id, enc_tok, enc_tt);
    return (n < 0 || (size_t)n >= url_len) ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* upload session bookkeeping (deterministic part-file naming)          */
/* ------------------------------------------------------------------ */

/* Part file path for an upload: {dir}/.{basename}.komari-upload-{id}.part
 * (Go newUploadSession), deterministic so upload_cancel can remove a part
 * after an agent restart without session state. */
static int part_file_path(const char *target, const char *upload_id,
                          char *out, size_t out_len) {
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", target);
    char *slash = strrchr(dir, '/');
    const char *base = target;
    if (slash) {
        *slash = '\0';
        base = slash + 1;
    }
    int n = snprintf(out, out_len, "%s/.%s.komari-upload-%s.part",
                     dir[0] ? dir : "/", base, upload_id);
    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* download_stream: agent uploads a file chunk as the request body      */
/* ------------------------------------------------------------------ */

typedef struct {
    int fd;
    off_t remaining;
    off_t pos;
} dl_reader_t;

/* Streaming body provider: reads the next chunk of the file. */
static ssize_t dl_reader_read(void *user, char *buf, size_t len) {
    dl_reader_t *r = (dl_reader_t *)user;
    if (r->remaining <= 0) return 0;
    size_t want = (size_t)r->remaining < len ? (size_t)r->remaining : len;
    ssize_t n = pread(r->fd, buf, want, r->pos);
    if (n <= 0) return -1;
    r->pos += n;
    r->remaining -= n;
    return n;
}

static cJSON *op_download_stream(const cJSON *args, const agent_config_t *config,
                                 char *err, size_t err_len) {
    const char *path_raw = args_str(args, "path");
    const char *transfer_id = args_str(args, "transfer_id");
    const char *transfer_token = args_str(args, "transfer_token");
    if (!path_raw || !transfer_id || !transfer_token) {
        snprintf(err, err_len, "invalid arguments");
        return NULL;
    }
    if (!transfer_id_valid(transfer_id) || !transfer_id_valid(transfer_token)) {
        snprintf(err, err_len, "invalid transfer identifier");
        return NULL;
    }
    long long offset = args_ll(args, "offset", 0);
    long long length = args_ll(args, "length", 0);
    long long file_size = args_ll(args, "file_size", 0);
    const char *modified_at = args_str(args, "modified_at");

    char path[1024];
    if (filemgr_resolve_path(path_raw, path, sizeof(path)) != 0) {
        snprintf(err, err_len, "invalid path");
        return NULL;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        snprintf(err, err_len, "open %s: %s", path, strerror(errno));
        return NULL;
    }

    /* Change detection: the panel sampled size/mtime when it planned the
     * transfer; a mismatch means the file changed mid-stream. */
    if (file_size > 0 && (long long)st.st_size != file_size) {
        snprintf(err, err_len, "file changed while opening stream");
        return NULL;
    }
    if (modified_at && modified_at[0]) {
        char now_iso[40];
        struct tm tm_utc;
        time_t mtime = st.st_mtim.tv_sec;
        gmtime_r(&mtime, &tm_utc);
        strftime(now_iso, sizeof(now_iso), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
        /* Compare the second-precision prefix; panels may send nanos. */
        size_t cmp = strlen(now_iso) - 1; /* drop the Z */
        if (strncmp(now_iso, modified_at, cmp) != 0) {
            snprintf(err, err_len, "file changed while opening stream");
            return NULL;
        }
    }

    if (length <= 0) {
        snprintf(err, err_len, "invalid length");
        return NULL;
    }

    dl_reader_t reader = {
        .fd = -1,
        .remaining = length,
        .pos = (off_t)offset,
    };

    char url[MAX_ENDPOINT_LEN + 128 + MAX_TOKEN_LEN * 3 + 512];
    if (build_transfer_url(config, transfer_id, transfer_token,
                           url, sizeof(url)) != 0) {
        snprintf(err, err_len, "transfer URL too long");
        return NULL;
    }

    char headers[512];
    snprintf(headers, sizeof(headers),
             "X-Komari-Transfer-ID: %s\r\n"
             "X-Komari-Transfer-Token: %s\r\n"
             "X-Komari-Transfer-Offset: %lld\r\n"
             "X-Komari-Transfer-Length: %lld\r\n"
             "Content-Type: application/octet-stream\r\n"
             "Accept: application/json\r\n"
             "Accept-Encoding: identity\r\n",
             transfer_id, transfer_token, offset, length);
    if (file_size > 0) {
        size_t len_now = strlen(headers);
        snprintf(headers + len_now, sizeof(headers) - len_now,
                 "Content-Range: bytes %lld-%lld/%lld\r\n",
                 offset, offset + length - 1, file_size);
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(err, err_len, "open %s: %s", path, strerror(errno));
        return NULL;
    }
    reader.fd = fd;

    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body_reader = dl_reader_read;
    req.body_user = &reader;
    req.body_len = (size_t)length; /* declared Content-Length */
    req.content_type = "application/octet-stream";
    req.extra_headers = headers;
    req.timeout_sec = TRANSFER_HTTP_TIMEOUT_SEC;
    req.ignore_cert = config->ignore_unsafe_cert;

    int ok = 0;
    if (http_client_request(&req, &resp) == 0 &&
        resp.status >= 200 && resp.status < 300) {
        ok = 1;
    } else if (resp.status >= 400 && resp.status < 500) {
        snprintf(err, err_len, "transfer rejected (%d)", resp.status);
    } else {
        snprintf(err, err_len, "transfer failed (status %d)", resp.status);
    }
    http_client_response_free(&resp);
    close(fd);

    if (!ok) return NULL;

    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sent", (double)length);
    return o;
}

/* ------------------------------------------------------------------ */
/* upload_stream: agent POSTs empty, reads the chunk from the response  */
/* ------------------------------------------------------------------ */

typedef struct {
    int fd;
    off_t base_offset;
    char err[256];
    int failed;
} upload_writer_t;

/* Streaming sink: pwrite the chunk into the part file at the declared
 * offset (Go offsetFileWriter). */
static int upload_writer(void *user, const char *data, size_t len) {
    upload_writer_t *w = (upload_writer_t *)user;
    if (w->failed) return -1;

    size_t off = 0;
    while (off < len) {
        ssize_t n = pwrite(w->fd, data + off, len - off, w->base_offset);
        if (n <= 0) {
            if (errno == EINTR) continue;
            snprintf(w->err, sizeof(w->err), "write: %s", strerror(errno));
            w->failed = 1;
            return -1;
        }
        w->base_offset += n;
        off += (size_t)n;
    }
    return 0;
}

static cJSON *op_upload_stream(const cJSON *args, const agent_config_t *config,
                               char *err, size_t err_len) {
    const char *path_raw = args_str(args, "path");
    const char *upload_id = args_str(args, "upload_id");
    const char *transfer_id = args_str(args, "transfer_id");
    const char *transfer_token = args_str(args, "transfer_token");
    if (!path_raw || !upload_id || !transfer_id || !transfer_token) {
        snprintf(err, err_len, "invalid arguments");
        return NULL;
    }
    if (!transfer_id_valid(upload_id) || !transfer_id_valid(transfer_id) ||
        !transfer_id_valid(transfer_token)) {
        snprintf(err, err_len, "invalid transfer identifier");
        return NULL;
    }
    long long offset = args_ll(args, "offset", 0);
    long long chunk_index = args_ll(args, "chunk_index", 0);
    long long chunk_size = args_ll(args, "chunk_size", 0);
    long long total_size = args_ll(args, "total_size", 0);
    bool first = args_bool(args, "first");

    char path[1024];
    if (filemgr_resolve_path(path_raw, path, sizeof(path)) != 0 ||
        strcmp(path, "/") == 0) {
        snprintf(err, err_len, "invalid path");
        return NULL;
    }

    /* Offset/chunk consistency (file_stream.go upload_stream). */
    if (offset != chunk_index * chunk_size) {
        snprintf(err, err_len, "offset %lld does not match chunk %lld",
                 offset, chunk_index);
        return NULL;
    }

    char part[1200];
    if (part_file_path(path, upload_id, part, sizeof(part)) != 0) {
        snprintf(err, err_len, "part path too long");
        return NULL;
    }

    /* First chunk creates/truncates the part file 0600. */
    int flags = O_WRONLY | O_CREAT;
    if (first) flags |= O_TRUNC;

    /* Ensure the parent directory exists for the first chunk. */
    if (first) {
        char dir[1024];
        snprintf(dir, sizeof(dir), "%s", path);
        char *slash = strrchr(dir, '/');
        if (slash && slash != dir) {
            *slash = '\0';
            /* MkdirAll-lite on the existing tree; final component errors are
             * surfaced by the part-file open below. */
            for (char *p = dir + 1; *p; p++) {
                if (*p == '/') {
                    *p = '\0';
                    mkdir(dir, 0755);
                    *p = '/';
                }
            }
        }
    }

    int fd = open(part, flags, 0600);
    if (fd < 0) {
        snprintf(err, err_len, "open %s: %s", part, strerror(errno));
        return NULL;
    }

    char url[MAX_ENDPOINT_LEN + 128 + MAX_TOKEN_LEN * 3 + 512];
    if (build_transfer_url(config, transfer_id, transfer_token,
                           url, sizeof(url)) != 0) {
        close(fd);
        snprintf(err, err_len, "transfer URL too long");
        return NULL;
    }

    char headers[512];
    snprintf(headers, sizeof(headers),
             "X-Komari-Transfer-ID: %s\r\n"
             "X-Komari-Transfer-Token: %s\r\n"
             "X-Komari-Transfer-Offset: %lld\r\n"
             "X-Komari-Transfer-Length: %lld\r\n"
             "Accept: application/octet-stream\r\n"
             "Accept-Encoding: identity\r\n",
             transfer_id, transfer_token, offset,
             (long long)0 /* length of the empty request body */);

    upload_writer_t writer = {.fd = fd, .base_offset = (off_t)offset,
                              .failed = 0, .err = ""};

    http_client_request_t req;
    http_client_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.url = url;
    req.body = ""; /* Empty body: the chunk arrives in the response. */
    req.extra_headers = headers;
    req.timeout_sec = TRANSFER_HTTP_TIMEOUT_SEC;
    req.ignore_cert = config->ignore_unsafe_cert;
    req.body_writer = upload_writer;
    req.writer_user = &writer;

    /* Expected chunk size for reporting the received count. */
    long long expected = chunk_size;
    if (total_size > 0 && offset + expected > total_size) {
        expected = total_size - offset; /* final partial chunk */
    }

    int ok = 0;
    if (http_client_request(&req, &resp) == 0 &&
        resp.status >= 200 && resp.status < 300 &&
        !writer.failed) {
        ok = 1;
    } else if (writer.failed) {
        snprintf(err, err_len, "%s", writer.err);
    } else if (resp.status >= 400 && resp.status < 500) {
        snprintf(err, err_len, "transfer rejected (%d)", resp.status);
    } else {
        snprintf(err, err_len, "transfer failed (status %d)", resp.status);
    }
    http_client_response_free(&resp);
    close(fd);

    if (!ok) return NULL;

    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "received", (double)expected);
    cJSON_AddNumberToObject(o, "offset", (double)(offset + expected));
    return o;
}

/* ------------------------------------------------------------------ */
/* upload_commit / upload_cancel                                       */
/* ------------------------------------------------------------------ */

static cJSON *op_upload_commit(const cJSON *args, const agent_config_t *config,
                               char *err, size_t err_len) {
    (void)config;
    const char *path_raw = args_str(args, "path");
    const char *upload_id = args_str(args, "upload_id");
    if (!path_raw || !upload_id) {
        snprintf(err, err_len, "invalid arguments");
        return NULL;
    }
    if (!transfer_id_valid(upload_id)) {
        snprintf(err, err_len, "invalid transfer identifier");
        return NULL;
    }
    long long total_size = args_ll(args, "total_size", 0);
    long long chunk_size = args_ll(args, "chunk_size", FILEMGR_CHUNK_DEFAULT);
    long long chunk_count = args_ll(args, "chunk_count", 0);
    if (chunk_size <= 0) chunk_size = FILEMGR_CHUNK_DEFAULT;
    if (chunk_size > (long long)FILEMGR_CHUNK_MAX) {
        snprintf(err, err_len, "chunk_size exceeds limit");
        return NULL;
    }
    /* Commit requires the full upload bookkeeping (Go commitFileUpload
     * demands totalSize > 0 && chunkCount > 0): without it the size check
     * below degenerates (expected_min <= 0) and an incomplete upload could
     * be published. */
    if (total_size <= 0 || chunk_count <= 0) {
        snprintf(err, err_len, "commit requires total_size and chunk_count");
        return NULL;
    }
    if (total_size > (long long)chunk_size * chunk_count) {
        snprintf(err, err_len, "total_size exceeds chunk geometry");
        return NULL;
    }

    char path[1024];
    if (filemgr_resolve_path(path_raw, path, sizeof(path)) != 0 ||
        strcmp(path, "/") == 0) {
        snprintf(err, err_len, "invalid path");
        return NULL;
    }

    /* Verify all chunks were received: the part file must be at least
     * chunk_size*(chunk_count-1)+1 bytes (all but the final chunk present;
     * files.go commit check). chunk_size <= FILEMGR_CHUNK_MAX and
     * total_size <= chunk_size*chunk_count bound the product. */
    char part[1200];
    if (part_file_path(path, upload_id, part, sizeof(part)) != 0) {
        snprintf(err, err_len, "part path too long");
        return NULL;
    }

    struct stat pst;
    if (stat(part, &pst) != 0) {
        snprintf(err, err_len, "stat %s: %s", part, strerror(errno));
        return NULL;
    }
    long long expected_min = chunk_size * (chunk_count - 1) + 1;
    if (total_size > 0 && (long long)pst.st_size < expected_min) {
        snprintf(err, err_len, "incomplete upload: %lld of %lld bytes",
                 (long long)pst.st_size, total_size);
        return NULL;
    }
    if ((long long)pst.st_size < total_size) {
        snprintf(err, err_len, "incomplete upload: %lld of %lld bytes",
                 (long long)pst.st_size, total_size);
        return NULL;
    }

    /* Truncate to total_size when the last chunk padded the file. */
    if ((long long)pst.st_size > total_size) {
        if (truncate(part, (off_t)total_size) != 0) {
            snprintf(err, err_len, "truncate %s: %s", part, strerror(errno));
            return NULL;
        }
    }

    /* Inherit permissions from an existing target file, else 0644. */
    mode_t mode = 0644;
    struct stat tst;
    if (stat(path, &tst) == 0) {
        mode = tst.st_mode & 07777;
    }

    /* Atomic publish: rename the part onto the target, then fsync the
     * directory (Go replaceFile). */
    if (rename(part, path) != 0) {
        snprintf(err, err_len, "rename %s: %s", path, strerror(errno));
        return NULL;
    }
    chmod(path, mode);
    {
        char dir[1024];
        snprintf(dir, sizeof(dir), "%s", path);
        char *slash = strrchr(dir, '/');
        int dfd = open(slash == dir ? "/" : dir, O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) {
            fsync(dfd);
            close(dfd);
        }
    }

    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "received", (double)total_size);
    cJSON_AddBoolToObject(o, "final", true);
    cJSON_AddNumberToObject(o, "offset", (double)total_size);
    return o;
}

static cJSON *op_upload_cancel(const cJSON *args, char *err, size_t err_len) {
    const char *path_raw = args_str(args, "path");
    const char *upload_id = args_str(args, "upload_id");
    if (!upload_id) {
        snprintf(err, err_len, "invalid arguments");
        return NULL;
    }
    if (!transfer_id_valid(upload_id)) {
        snprintf(err, err_len, "invalid transfer identifier");
        return NULL;
    }

    if (path_raw) {
        char path[1024];
        if (filemgr_resolve_path(path_raw, path, sizeof(path)) == 0) {
            char part[1200];
            if (part_file_path(path, upload_id, part, sizeof(part)) == 0) {
                unlink(part); /* Deterministic path: works after a restart. */
            }
        }
    }

    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "cancelled", true);
    return o;
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                            */
/* ------------------------------------------------------------------ */

cJSON *filemgr_stream_op(const char *op, const cJSON *args,
                         const agent_config_t *config, char *err,
                         size_t err_len) {
    if (strcmp(op, "download_stream") == 0) {
        return op_download_stream(args, config, err, err_len);
    }
    if (strcmp(op, "upload_stream") == 0) {
        return op_upload_stream(args, config, err, err_len);
    }
    if (strcmp(op, "upload_commit") == 0) {
        return op_upload_commit(args, config, err, err_len);
    }
    if (strcmp(op, "upload_cancel") == 0) {
        return op_upload_cancel(args, err, err_len);
    }
    snprintf(err, err_len, "unsupported stream op: %s", op);
    return NULL;
}
