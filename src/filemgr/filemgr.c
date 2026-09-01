/*
 * File manager operations implementation, mirroring server/files.go.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#define _GNU_SOURCE

#include "filemgr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "logger.h"
#include "http_client.h"
#include "jsonrpc.h"
#include "v2.h"
#include "filemgr_stream.h"

/* ------------------------------------------------------------------ */
/* Concurrency gate                                                    */
/* ------------------------------------------------------------------ */

static sem_t g_op_sem;
static pthread_once_t g_op_sem_once = PTHREAD_ONCE_INIT;

/* One-time initializer: handle_file_params is invoked from both the WS
 * recv thread and the fallback thread, so a lazy check-then-init on a
 * plain bool could double-initialize the semaphore. */
static void filemgr_sem_init_once(void) {
    sem_init(&g_op_sem, 0, FILEMGR_MAX_CONCURRENT);
}

static void filemgr_sem_ensure(void) {
    pthread_once(&g_op_sem_once, filemgr_sem_init_once);
}

int filemgr_try_acquire(void) {
    filemgr_sem_ensure();
    return (sem_trywait(&g_op_sem) == 0) ? 0 : -1;
}

void filemgr_release(void) {
    filemgr_sem_ensure();
    sem_post(&g_op_sem);
}

bool filemgr_allowed(const agent_config_t *config) {
    return config && !config->disable_web_ssh;
}

/* ------------------------------------------------------------------ */
/* Shared helpers (also used by filemgr_stream.c)                      */
/* ------------------------------------------------------------------ */

/* Resolve a request path: expand a leading ~ to the agent user's home,
 * then lexically clean the result (collapse //, /./, /../). Rejects
 * control characters. Returns 0 and fills out on success. Mirrors the Go
 * resolveFilePath. */
int filemgr_resolve_path(const char *raw, char *out, size_t out_len) {
    if (!raw || !raw[0] || !out) return -1;
    for (const char *p = raw; *p; p++) {
        if ((unsigned char)*p < 0x20) return -1; /* CR/LF injection */
    }

    char expanded[1024];
    if (raw[0] == '~') {
        const char *home = getenv("HOME");
        if (!home || !home[0]) home = "/";
        snprintf(expanded, sizeof(expanded), "%s%s", home, raw + 1);
    } else {
        snprintf(expanded, sizeof(expanded), "%s", raw);
    }

    const char *parts[256];
    int nparts = 0;
    char work[1024];
    snprintf(work, sizeof(work), "%s", expanded);
    char *save = NULL;
    for (char *tok = strtok_r(work, "/", &save); tok;
         tok = strtok_r(NULL, "/", &save)) {
        if (strcmp(tok, ".") == 0) continue;
        if (strcmp(tok, "..") == 0) {
            if (nparts > 0) nparts--;
            continue;
        }
        /* Overlong paths must be rejected, not silently truncated: a
         * truncated path resolves to a different file, which is dangerous
         * for destructive ops like delete. */
        if (nparts >= (int)(sizeof(parts) / sizeof(parts[0]))) {
            errno = ENAMETOOLONG;
            return -1;
        }
        parts[nparts++] = tok;
    }

    size_t off = 0;
    /* Absolute-ness is judged after ~ expansion (a "~"-path whose HOME is
     * absolute resolves to an absolute path). */
    bool is_absolute = (expanded[0] == '/');
    if (is_absolute) {
        off += (size_t)snprintf(out, out_len, "/");
    }
    for (int i = 0; i < nparts && off < out_len; i++) {
        if (off > 0 && out[off - 1] != '/') {
            off += (size_t)snprintf(out + off, out_len - off, "/");
        }
        off += (size_t)snprintf(out + off, out_len - off, "%s", parts[i]);
    }
    if (off == 0) snprintf(out, out_len, "%s", is_absolute ? "/" : ".");
    return 0;
}

/* Build "<endpoint>/api/clients/v2/rpc?token=<encoded>" (shared with the
 * streaming ops). */
int filemgr_build_rpc_url(const agent_config_t *config, char *url, size_t url_len) {
    if (!config || !url) return -1;
    static const char hex[] = "0123456789ABCDEF";
    char encoded[MAX_TOKEN_LEN * 3 + 1];
    size_t j = 0;
    for (const char *p = config->token; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            if (j + 1 >= sizeof(encoded)) return -1;
            encoded[j++] = (char)c;
        } else {
            if (j + 3 >= sizeof(encoded)) return -1;
            encoded[j++] = '%';
            encoded[j++] = hex[(c >> 4) & 0xF];
            encoded[j++] = hex[c & 0xF];
        }
    }
    encoded[j] = '\0';
    int n = snprintf(url, url_len, "%s%s?token=%s",
                     config->endpoint, V2_RPC_ENDPOINT, encoded);
    return (n < 0 || (size_t)n >= url_len) ? -1 : 0;
}

/* Recursive directory removal used by delete (RemoveAll semantics) and the
 * move EXDEV fallback. depth bounds symlink-cycle protection. */
int filemgr_remove_tree(const char *path, int depth) {
    if (depth > 64) { errno = ELOOP; return -1; }

    DIR *dir = opendir(path);
    if (!dir) return unlink(path);

    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(dir)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", path, de->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) { rc = -1; break; }
        if (S_ISDIR(st.st_mode)) {
            rc = filemgr_remove_tree(full, depth + 1);
        } else {
            rc = unlink(full);
        }
    }
    closedir(dir);
    if (rc != 0) return rc;
    return rmdir(path);
}

/* ------------------------------------------------------------------ */
/* fileInfo construction (files.go fileInfo)                           */
/* ------------------------------------------------------------------ */

static cJSON *fileinfo_from_stat(const char *name, const char *path,
                                 const struct stat *st) {
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;

    cJSON_AddStringToObject(o, "name", name);
    cJSON_AddStringToObject(o, "path", path);
    cJSON_AddBoolToObject(o, "is_dir", S_ISDIR(st->st_mode));
    cJSON_AddBoolToObject(o, "is_symlink", S_ISLNK(st->st_mode));
    cJSON_AddNumberToObject(o, "size", (double)st->st_size);

    char mode_str[16];
    snprintf(mode_str, sizeof(mode_str), "%c%c%c%c%c%c%c%c%c%c",
             S_ISDIR(st->st_mode) ? 'd' : S_ISLNK(st->st_mode) ? 'l' : '-',
             (st->st_mode & S_IRUSR) ? 'r' : '-',
             (st->st_mode & S_IWUSR) ? 'w' : '-',
             (st->st_mode & S_IXUSR) ? 'x' : '-',
             (st->st_mode & S_IRGRP) ? 'r' : '-',
             (st->st_mode & S_IWGRP) ? 'w' : '-',
             (st->st_mode & S_IXGRP) ? 'x' : '-',
             (st->st_mode & S_IROTH) ? 'r' : '-',
             (st->st_mode & S_IWOTH) ? 'w' : '-',
             (st->st_mode & S_IXOTH) ? 'x' : '-');
    cJSON_AddStringToObject(o, "mode", mode_str);

    char octal[12];
    snprintf(octal, sizeof(octal), "%04o", (unsigned)(st->st_mode & 07777));
    cJSON_AddStringToObject(o, "mode_octal", octal);

    cJSON_AddNumberToObject(o, "uid", (double)st->st_uid);
    cJSON_AddNumberToObject(o, "gid", (double)st->st_gid);

    struct passwd *pw = getpwuid(st->st_uid);
    cJSON_AddStringToObject(o, "owner", pw && pw->pw_name ? pw->pw_name : "");
    struct group *gr = getgrgid(st->st_gid);
    cJSON_AddStringToObject(o, "group", gr && gr->gr_name ? gr->gr_name : "");

    char ts[40];
    struct tm tm_utc;
    time_t mtime = st->st_mtim.tv_sec;
    gmtime_r(&mtime, &tm_utc);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    cJSON_AddStringToObject(o, "modified_at", ts);

    return o;
}

/* lstat + symlink enrichment: for symlinks re-stat the target and keep the
 * link target string (files.go behavior). */
static cJSON *fileinfo_build(const char *name, const char *path) {
    struct stat lst, st;
    if (lstat(path, &lst) != 0) return NULL;
    if (!S_ISLNK(lst.st_mode)) {
        return fileinfo_from_stat(name, path, &lst);
    }
    if (stat(path, &st) != 0) st = lst;
    cJSON *o = fileinfo_from_stat(name, path, &st);
    if (o) {
        char target[1024];
        ssize_t n = readlink(path, target, sizeof(target) - 1);
        if (n >= 0) {
            target[n] = '\0';
            cJSON_AddStringToObject(o, "target", target);
        }
    }
    return o;
}

/* ------------------------------------------------------------------ */
/* Non-streaming ops                                                   */
/* ------------------------------------------------------------------ */

static cJSON *op_list(const cJSON *args, char *err, size_t err_len) {
    cJSON *path_item = cJSON_GetObjectItem(args, "path");
    const char *raw = (path_item && cJSON_IsString(path_item)) ? path_item->valuestring : "";
    char path[1024];
    if (filemgr_resolve_path(raw, path, sizeof(path)) != 0) {
        snprintf(err, err_len, "invalid path");
        return NULL;
    }

    DIR *dir = opendir(path);
    if (!dir) {
        snprintf(err, err_len, "open %s: %s", path, strerror(errno));
        return NULL;
    }

    /* Per-invocation heap buffers (up to ~1.25 MiB total): op_list runs on
     * up to FILEMGR_MAX_CONCURRENT concurrent workers, so static buffers
     * here would race and interleave entries across responses. */
    enum { MAX_ENTRIES = 4096 };
    char (*names)[256] = malloc(sizeof(*names) * MAX_ENTRIES);
    bool *is_dirs = malloc(sizeof(bool) * MAX_ENTRIES);
    if (!names || !is_dirs) {
        free(names);
        free(is_dirs);
        closedir(dir);
        snprintf(err, err_len, "out of memory");
        return NULL;
    }
    int n = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL && n < MAX_ENTRIES) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        snprintf(names[n], sizeof(names[n]), "%s", de->d_name);
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", path, de->d_name);
        struct stat st;
        is_dirs[n] = (lstat(full, &st) == 0 && S_ISDIR(st.st_mode));
        n++;
    }
    closedir(dir);

    /* Sort: directories first, then case-insensitive name order. */
    for (int i = 1; i < n; i++) {
        for (int j = i; j > 0; j--) {
            bool di = is_dirs[j], dj = is_dirs[j - 1];
            int cmp = strcasecmp(names[j], names[j - 1]);
            bool swap = (di && !dj) || (di == dj && cmp < 0);
            if (!swap) break;
            char tmp[256];
            memcpy(tmp, names[j], sizeof(tmp));
            memcpy(names[j], names[j - 1], sizeof(tmp));
            memcpy(names[j - 1], tmp, sizeof(tmp));
            bool tb = is_dirs[j];
            is_dirs[j] = is_dirs[j - 1];
            is_dirs[j - 1] = tb;
        }
    }

    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", path, names[i]);
        cJSON *fi = fileinfo_build(names[i], full);
        if (fi) cJSON_AddItemToArray(arr, fi);
    }
    free(names);
    free(is_dirs);
    return arr;
}

static cJSON *op_stat(const cJSON *args, char *err, size_t err_len) {
    cJSON *path_item = cJSON_GetObjectItem(args, "path");
    const char *raw = (path_item && cJSON_IsString(path_item)) ? path_item->valuestring : "";
    char path[1024];
    if (filemgr_resolve_path(raw, path, sizeof(path)) != 0) {
        snprintf(err, err_len, "invalid path");
        return NULL;
    }
    char name[256];
    const char *slash = strrchr(path, '/');
    snprintf(name, sizeof(name), "%s", slash ? slash + 1 : path);
    cJSON *fi = fileinfo_build(name, path);
    if (!fi) snprintf(err, err_len, "stat %s: %s", path, strerror(errno));
    return fi;
}

static cJSON *op_list_roots(char *err, size_t err_len) {
    (void)err; (void)err_len;
    cJSON *arr = cJSON_CreateArray();
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "name", "/");
    cJSON_AddStringToObject(root, "path", "/");
    cJSON_AddBoolToObject(root, "is_dir", true);
    cJSON_AddItemToArray(arr, root);
    return arr;
}

static cJSON *op_create(const cJSON *args, char *err, size_t err_len) {
    cJSON *path_item = cJSON_GetObjectItem(args, "path");
    const char *raw = (path_item && cJSON_IsString(path_item)) ? path_item->valuestring : "";
    char path[1024];
    if (filemgr_resolve_path(raw, path, sizeof(path)) != 0 || strcmp(path, "/") == 0) {
        snprintf(err, err_len, "invalid path");
        return NULL;
    }

    /* MkdirAll semantics on the parent (Go createFile). */
    char parent[1024];
    snprintf(parent, sizeof(parent), "%s", path);
    char *pslash = strrchr(parent, '/');
    if (pslash && pslash != parent) {
        *pslash = '\0';
        for (char *p = parent + 1; *p; p++) {
            if (*p == '/') {
                *p = '\0';
                if (mkdir(parent, 0755) != 0 && errno != EEXIST) {
                    snprintf(err, err_len, "mkdir %s: %s", parent, strerror(errno));
                    return NULL;
                }
                *p = '/';
            }
        }
        if (mkdir(parent, 0755) != 0 && errno != EEXIST) {
            snprintf(err, err_len, "mkdir %s: %s", parent, strerror(errno));
            return NULL;
        }
    }

    /* Reject replacing a directory with a file (Go createFile). */
    struct stat pst;
    if (lstat(path, &pst) == 0 && S_ISDIR(pst.st_mode)) {
        snprintf(err, err_len, "cannot replace a directory with a file");
        return NULL;
    }

    /* Exclusive randomly-suffixed temp file (Go os.CreateTemp): a fixed
     * pid-based name would collide between concurrent create ops on the
     * same path. */
    char tmp[1024];
    unsigned seq = (unsigned)((uintptr_t)pthread_self() ^ (uintptr_t)time(NULL));
    snprintf(tmp, sizeof(tmp), "%s.komari-empty-%d-%u", path, (int)getpid(), seq & 0xFFFF);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0644);
    for (int retry = 0; fd < 0 && errno == EEXIST && retry < 8; retry++) {
        seq = seq * 1103515245u + 12345u;
        snprintf(tmp, sizeof(tmp), "%s.komari-empty-%d-%u",
                 path, (int)getpid(), seq & 0xFFFF);
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0644);
    }
    if (fd < 0) {
        snprintf(err, err_len, "create %s: %s", path, strerror(errno));
        return NULL;
    }
    close(fd);

    if (lstat(path, &pst) == 0) {
        chmod(tmp, pst.st_mode & 07777);
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        snprintf(err, err_len, "rename %s: %s", path, strerror(errno));
        return NULL;
    }

    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "created", true);
    cJSON_AddNumberToObject(o, "size", 0);
    return o;
}

static cJSON *op_mkdir(const cJSON *args, char *err, size_t err_len) {
    cJSON *path_item = cJSON_GetObjectItem(args, "path");
    const char *raw = (path_item && cJSON_IsString(path_item)) ? path_item->valuestring : "";
    char path[1024];
    if (filemgr_resolve_path(raw, path, sizeof(path)) != 0 || strcmp(path, "/") == 0) {
        snprintf(err, err_len, "invalid path");
        return NULL;
    }

    mode_t mode = 0755;
    cJSON *mode_item = cJSON_GetObjectItem(args, "mode");
    if (mode_item && cJSON_IsString(mode_item) && mode_item->valuestring) {
        const char *m = mode_item->valuestring;
        if (m[0] == '0' && (m[1] == 'o' || m[1] == 'O')) m += 2;
        mode = (mode_t)strtoul(m, NULL, 8);
    }

    /* MkdirAll semantics: create every missing component. */
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                snprintf(err, err_len, "mkdir %s: %s", tmp, strerror(errno));
                return NULL;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        snprintf(err, err_len, "mkdir %s: %s", tmp, strerror(errno));
        return NULL;
    }

    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "created", true);
    return o;
}

static cJSON *op_delete(const cJSON *args, char *err, size_t err_len) {
    cJSON *path_item = cJSON_GetObjectItem(args, "path");
    const char *raw = (path_item && cJSON_IsString(path_item)) ? path_item->valuestring : "";
    char path[1024];
    if (filemgr_resolve_path(raw, path, sizeof(path)) != 0 || strcmp(path, "/") == 0) {
        snprintf(err, err_len, "refusing to delete root");
        return NULL;
    }

    struct stat st;
    if (lstat(path, &st) != 0) {
        snprintf(err, err_len, "remove %s: %s", path, strerror(errno));
        return NULL;
    }
    int rc;
    if (S_ISDIR(st.st_mode)) {
        rc = filemgr_remove_tree(path, 0);
    } else {
        rc = unlink(path);
    }
    if (rc != 0) {
        snprintf(err, err_len, "remove %s: %s", path, strerror(errno));
        return NULL;
    }

    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "deleted", true);
    return o;
}

static int copy_entry(const char *src, const char *dst, int depth);

static int copy_recursive(const char *src, const char *dst, int depth) {
    if (depth > 64) { errno = ELOOP; return -1; }
    DIR *dir = opendir(src);
    if (!dir) return -1;
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(dir)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char s[1024], d[1024];
        snprintf(s, sizeof(s), "%s/%s", src, de->d_name);
        snprintf(d, sizeof(d), "%s/%s", dst, de->d_name);
        rc = copy_entry(s, d, depth);
    }
    closedir(dir);
    return rc;
}

static int copy_entry(const char *src, const char *dst, int depth) {
    struct stat st;
    if (lstat(src, &st) != 0) return -1;

    if (S_ISLNK(st.st_mode)) {
        char target[1024];
        ssize_t n = readlink(src, target, sizeof(target) - 1);
        if (n < 0) return -1;
        target[n] = '\0';
        unlink(dst);
        return symlink(target, dst);
    }
    if (S_ISDIR(st.st_mode)) {
        if (mkdir(dst, st.st_mode & 07777) != 0 && errno != EEXIST) return -1;
        return copy_recursive(src, dst, depth + 1);
    }

    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 07777);
    if (out < 0) { close(in); return -1; }

    char buf[65536];
    ssize_t r;
    while ((r = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < r) {
            ssize_t w = write(out, buf + off, (size_t)(r - off));
            if (w <= 0) {
                if (errno == EINTR) continue;
                r = -1;
                break;
            }
            off += w;
        }
        if (r < 0) break;
    }
    close(in);
    close(out);
    if (r < 0) return -1;

    /* Preserve mode and timestamps (Go Chmod + Chtimes). */
    chmod(dst, st.st_mode & 07777);
    struct timespec times[2] = {st.st_atim, st.st_mtim};
    utimensat(AT_FDCWD, dst, times, 0);
    return 0;
}

/* True when dst lies strictly inside src (src itself, src/... subtree).
 * Mirrors the Go pathContains (files.go): a prefix match only counts as
 * containment when the next character is a separator, so /a/b -> /a/b2
 * (a sibling) is allowed while /a/b -> /a/b/c (a child) is rejected. */
static bool path_contains(const char *src, const char *dst) {
    size_t n = strlen(src);
    if (strncmp(dst, src, n) != 0) return false;
    if (dst[n] == '\0') return true; /* identical path */
    return dst[n] == '/';
}

static cJSON *op_copy(const cJSON *args, char *err, size_t err_len) {
    cJSON *s_item = cJSON_GetObjectItem(args, "source");
    cJSON *d_item = cJSON_GetObjectItem(args, "destination");
    const char *s_raw = (s_item && cJSON_IsString(s_item)) ? s_item->valuestring : "";
    const char *d_raw = (d_item && cJSON_IsString(d_item)) ? d_item->valuestring : "";
    char src[1024], dst[1024];
    if (filemgr_resolve_path(s_raw, src, sizeof(src)) != 0 ||
        filemgr_resolve_path(d_raw, dst, sizeof(dst)) != 0) {
        snprintf(err, err_len, "invalid path");
        return NULL;
    }
    if (path_contains(src, dst)) {
        snprintf(err, err_len, "cannot copy into itself");
        return NULL;
    }
    if (copy_entry(src, dst, 0) != 0) {
        snprintf(err, err_len, "copy %s: %s", src, strerror(errno));
        return NULL;
    }
    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "copied", true);
    return o;
}

static cJSON *op_move(const cJSON *args, char *err, size_t err_len) {
    cJSON *s_item = cJSON_GetObjectItem(args, "source");
    cJSON *d_item = cJSON_GetObjectItem(args, "destination");
    const char *s_raw = (s_item && cJSON_IsString(s_item)) ? s_item->valuestring : "";
    const char *d_raw = (d_item && cJSON_IsString(d_item)) ? d_item->valuestring : "";
    char src[1024], dst[1024];
    if (filemgr_resolve_path(s_raw, src, sizeof(src)) != 0 ||
        filemgr_resolve_path(d_raw, dst, sizeof(dst)) != 0) {
        snprintf(err, err_len, "invalid path");
        return NULL;
    }
    if (path_contains(src, dst)) {
        snprintf(err, err_len, "cannot move into itself");
        return NULL;
    }
    if (rename(src, dst) == 0) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddBoolToObject(o, "moved", true);
        return o;
    }
    if (errno != EXDEV) {
        snprintf(err, err_len, "move %s: %s", src, strerror(errno));
        return NULL;
    }
    /* Cross-device: copy then delete (Go EXDEV fallback). */
    if (copy_entry(src, dst, 0) != 0) {
        snprintf(err, err_len, "copy %s: %s", src, strerror(errno));
        return NULL;
    }
    struct stat st;
    if (lstat(src, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (filemgr_remove_tree(src, 0) != 0) {
            snprintf(err, err_len, "cleanup %s: %s", src, strerror(errno));
            return NULL;
        }
    } else if (unlink(src) != 0) {
        snprintf(err, err_len, "unlink %s: %s", src, strerror(errno));
        return NULL;
    }
    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "moved", true);
    return o;
}

static cJSON *op_chmod(const cJSON *args, char *err, size_t err_len) {
    cJSON *path_item = cJSON_GetObjectItem(args, "path");
    cJSON *mode_item = cJSON_GetObjectItem(args, "mode");
    const char *raw = (path_item && cJSON_IsString(path_item)) ? path_item->valuestring : "";
    char path[1024];
    if (filemgr_resolve_path(raw, path, sizeof(path)) != 0 ||
        !mode_item || !cJSON_IsString(mode_item) || !mode_item->valuestring) {
        snprintf(err, err_len, "invalid arguments");
        return NULL;
    }

    /* parseMode: strip a "0o" prefix, parse octal (Go parseMode). */
    const char *m = mode_item->valuestring;
    if (m[0] == '0' && (m[1] == 'o' || m[1] == 'O')) m += 2;
    char *end = NULL;
    unsigned long mode = strtoul(m, &end, 8);
    if (!end || *end != '\0') {
        snprintf(err, err_len, "invalid mode");
        return NULL;
    }
    if (chmod(path, (mode_t)(mode & 07777)) != 0) {
        snprintf(err, err_len, "chmod %s: %s", path, strerror(errno));
        return NULL;
    }

    char octal[12];
    snprintf(octal, sizeof(octal), "%04lo", mode & 07777);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "mode", octal);
    return o;
}

static cJSON *op_chown(const cJSON *args, char *err, size_t err_len) {
    cJSON *path_item = cJSON_GetObjectItem(args, "path");
    const char *raw = (path_item && cJSON_IsString(path_item)) ? path_item->valuestring : "";
    char path[1024];
    if (filemgr_resolve_path(raw, path, sizeof(path)) != 0) {
        snprintf(err, err_len, "invalid path");
        return NULL;
    }

    uid_t uid = (uid_t)-1;
    gid_t gid = (gid_t)-1;

    cJSON *uid_item = cJSON_GetObjectItem(args, "uid");
    cJSON *owner_item = cJSON_GetObjectItem(args, "owner");
    if (uid_item && cJSON_IsNumber(uid_item)) {
        uid = (uid_t)uid_item->valueint;
    } else if (owner_item && cJSON_IsString(owner_item) && owner_item->valuestring[0]) {
        struct passwd *pw = getpwnam(owner_item->valuestring);
        if (!pw) {
            snprintf(err, err_len, "unknown owner: %s", owner_item->valuestring);
            return NULL;
        }
        uid = pw->pw_uid;
    }

    cJSON *gid_item = cJSON_GetObjectItem(args, "gid");
    cJSON *group_item = cJSON_GetObjectItem(args, "group");
    if (gid_item && cJSON_IsNumber(gid_item)) {
        gid = (gid_t)gid_item->valueint;
    } else if (group_item && cJSON_IsString(group_item) && group_item->valuestring[0]) {
        struct group *gr = getgrnam(group_item->valuestring);
        if (!gr) {
            snprintf(err, err_len, "unknown group: %s", group_item->valuestring);
            return NULL;
        }
        gid = gr->gr_gid;
    }

    if (chown(path, uid, gid) != 0) {
        snprintf(err, err_len, "chown %s: %s", path, strerror(errno));
        return NULL;
    }

    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "uid", uid == (uid_t)-1 ? -1 : (double)uid);
    cJSON_AddNumberToObject(o, "gid", gid == (gid_t)-1 ? -1 : (double)gid);
    return o;
}

/* ------------------------------------------------------------------ */
/* Search                                                              */
/* ------------------------------------------------------------------ */

static void search_walk(const char *dir_path, const char *name_query,
                        bool content_mode, const char *content_query,
                        cJSON *matches, bool *limited, int depth);

static void search_add_match(cJSON *matches, const char *path,
                             const char *text, bool *limited) {
    if (*limited) return;
    if (cJSON_GetArraySize(matches) >= FILEMGR_SEARCH_LIMIT) {
        *limited = true;
        return;
    }
    cJSON *m = cJSON_CreateObject();
    cJSON_AddStringToObject(m, "path", path);
    if (text) {
        char snippet[301];
        snprintf(snippet, sizeof(snippet), "%s", text);
        cJSON_AddStringToObject(m, "text", snippet);
    }
    cJSON_AddItemToArray(matches, m);
}

static void search_walk(const char *dir_path, const char *name_query,
                        bool content_mode, const char *content_query,
                        cJSON *matches, bool *limited, int depth) {
    if (*limited || depth > 32) return;

    DIR *dir = opendir(dir_path);
    if (!dir) return;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL && !*limited) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir_path, de->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            search_walk(full, name_query, content_mode, content_query,
                        matches, limited, depth + 1);
            continue;
        }

        if (!content_mode) {
            /* Name search: case-insensitive substring on the file name. */
            if (strcasestr(de->d_name, name_query) != NULL) {
                search_add_match(matches, full, NULL, limited);
            }
            continue;
        }

        /* Content search: regular files <= 10 MB, line-by-line, first hit
         * per file with a 300-byte snippet (Go searchFiles). */
        if (!S_ISREG(st.st_mode) || st.st_size > FILEMGR_SEARCH_CONTENT_MAX) continue;

        FILE *fp = fopen(full, "r");
        if (!fp) continue;
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            if (strcasestr(line, content_query) != NULL) {
                line[strcspn(line, "\r\n")] = '\0';
                search_add_match(matches, full, line, limited);
                break;
            }
        }
        fclose(fp);
    }
    closedir(dir);
}

static cJSON *op_search(const cJSON *args, char *err, size_t err_len) {
    cJSON *q_item = cJSON_GetObjectItem(args, "query");
    cJSON *c_item = cJSON_GetObjectItem(args, "content");
    cJSON *p_item = cJSON_GetObjectItem(args, "path");
    const char *query = (q_item && cJSON_IsString(q_item)) ? q_item->valuestring : "";
    bool content_mode = c_item && cJSON_IsTrue(c_item);
    const char *p_raw = (p_item && cJSON_IsString(p_item)) ? p_item->valuestring : "~";

    char path[1024];
    if (filemgr_resolve_path(p_raw, path, sizeof(path)) != 0 || !query[0]) {
        snprintf(err, err_len, "invalid arguments");
        return NULL;
    }

    cJSON *o = cJSON_CreateObject();
    cJSON *matches = cJSON_CreateArray();
    bool limited = false;
    search_walk(path, query, content_mode, query, matches, &limited, 0);
    cJSON_AddItemToObject(o, "matches", matches);
    cJSON_AddBoolToObject(o, "limited", limited);
    return o;
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                            */
/* ------------------------------------------------------------------ */

cJSON *filemgr_execute(const agent_config_t *config, const cJSON *params) {
    if (!config || !params || !cJSON_IsObject(params)) return NULL;

    cJSON *uuid = cJSON_GetObjectItem(params, "uuid");
    cJSON *req_id = cJSON_GetObjectItem(params, "request_id");
    cJSON *op_item = cJSON_GetObjectItem(params, "op");
    cJSON *args = cJSON_GetObjectItem(params, "args");
    /* Synthesize an empty args object when absent/not an object; track
     * ownership so the worker's result-driven flow cannot leak it. */
    cJSON *args_owned = NULL;
    if (!cJSON_IsObject(args)) {
        args_owned = cJSON_CreateObject();
        if (!args_owned) return NULL;
        args = args_owned;
    }

    const char *op = (op_item && cJSON_IsString(op_item) && op_item->valuestring)
                         ? op_item->valuestring : "";

    char err[512] = "";
    cJSON *result = NULL;
    bool ok = true;

    if (strcmp(op, "list") == 0) {
        result = op_list(args, err, sizeof(err));
    } else if (strcmp(op, "list_roots") == 0) {
        result = op_list_roots(err, sizeof(err));
    } else if (strcmp(op, "stat") == 0) {
        result = op_stat(args, err, sizeof(err));
    } else if (strcmp(op, "create") == 0) {
        result = op_create(args, err, sizeof(err));
    } else if (strcmp(op, "mkdir") == 0) {
        result = op_mkdir(args, err, sizeof(err));
    } else if (strcmp(op, "delete") == 0) {
        result = op_delete(args, err, sizeof(err));
    } else if (strcmp(op, "move") == 0) {
        result = op_move(args, err, sizeof(err));
    } else if (strcmp(op, "copy") == 0) {
        result = op_copy(args, err, sizeof(err));
    } else if (strcmp(op, "chmod") == 0) {
        result = op_chmod(args, err, sizeof(err));
    } else if (strcmp(op, "chown") == 0) {
        result = op_chown(args, err, sizeof(err));
    } else if (strcmp(op, "search") == 0) {
        result = op_search(args, err, sizeof(err));
    } else if (strcmp(op, "download_stream") == 0 ||
               strcmp(op, "upload_stream") == 0 ||
               strcmp(op, "upload_commit") == 0 ||
               strcmp(op, "upload_cancel") == 0) {
        result = filemgr_stream_op(op, args, config, err, sizeof(err));
    } else {
        ok = false;
        snprintf(err, sizeof(err), "unsupported op: %s", op);
    }

    if (!result) ok = false;

    cJSON_Delete(args_owned);
    args_owned = NULL;
    args = NULL;

    cJSON *out = cJSON_CreateObject();
    if (!out) {
        cJSON_Delete(result);
        return NULL;
    }
    if (uuid && cJSON_IsString(uuid)) {
        cJSON_AddStringToObject(out, "uuid", uuid->valuestring);
    } else {
        cJSON_AddNullToObject(out, "uuid");
    }
    if (req_id && cJSON_IsString(req_id)) {
        cJSON_AddStringToObject(out, "request_id", req_id->valuestring);
    } else if (req_id && cJSON_IsNumber(req_id)) {
        cJSON_AddNumberToObject(out, "request_id", req_id->valuedouble);
    } else {
        cJSON_AddNullToObject(out, "request_id");
    }
    cJSON_AddBoolToObject(out, "ok", ok);
    if (result) {
        cJSON_AddItemToObject(out, "result", result);
        cJSON_AddNullToObject(out, "error");
    } else {
        cJSON_AddNullToObject(out, "result");
        cJSON_AddStringToObject(out, "error", err);
    }
    return out;
}

int filemgr_upload_result(const agent_config_t *config, cJSON *result_params) {
    if (!config || !result_params) return -1;

    /* Request wrapper: id=null per Go NewRequest(nil, ...). */
    cJSON *request = cJSON_CreateObject();
    if (!request) {
        cJSON_Delete(result_params);
        return -1;
    }
    cJSON_AddStringToObject(request, "jsonrpc", "2.0");
    cJSON_AddNullToObject(request, "id");
    cJSON_AddStringToObject(request, "method", AGENT_FILE_RESULT);
    cJSON_AddItemToObject(request, "params", result_params);

    char *body = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);
    if (!body) return -1;

    char url[MAX_ENDPOINT_LEN + 64 + MAX_TOKEN_LEN * 3 + 1];
    if (filemgr_build_rpc_url(config, url, sizeof(url)) != 0) {
        free(body);
        return -1;
    }

    /* POST with 4 attempts and attempt*500 ms backoff; 4xx aborts
     * (mirrors files.go sendFileResult). Not compressed (Go sends the
     * file result uncompressed). */
    int ret = -1;
    for (int attempt = 1; attempt <= 4; attempt++) {
        http_client_request_t req;
        http_client_response_t resp;
        memset(&req, 0, sizeof(req));
        memset(&resp, 0, sizeof(resp));
        req.url = url;
        req.body = body;
        req.ignore_cert = config->ignore_unsafe_cert;
        req.timeout_sec = 60;

        int status = 0;
        if (http_client_request(&req, &resp) == 0) {
            status = resp.status;
        }
        http_client_response_free(&resp);

        if (status >= 200 && status < 300) {
            ret = 0;
            break;
        }
        if (status >= 400 && status < 500) {
            KOMARI_LOG_WARN("[FileMgr] Result upload rejected (%d), aborting", status);
            break;
        }
        if (attempt < 4) {
            struct timespec ts = {.tv_sec = 0,
                                  .tv_nsec = (long)attempt * 500 * 1000 * 1000};
            nanosleep(&ts, NULL);
        }
    }
    free(body);
    return ret;
}
