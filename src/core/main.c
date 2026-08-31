/*
 * Komari Agent entry point: argument parsing, configuration loading,
 * WebSocket connection, reporting/heartbeat threads and Web SSH
 * terminal session handling.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#include "config.h"
#include "monitoring.h"
#include "websocket.h"
#include "report.h"
#include "netstatic.h"
#include "terminal.h"
#include "utils.h"
#include "logger.h"
#include "ping.h"
#include "virtual.h"
#include "idn.h"
#include "version.h"
#include "cJSON.h"
#include "autodiscovery.h"
#include "paths.h"
#include "update.h"
#include "jsonrpc.h"
#include "fallback.h"
#include "v2.h"
#include "filemgr.h"

#define DEFAULT_INTERVAL 1.0

static volatile sig_atomic_t g_running = 1;
static agent_config_t g_config;
static ws_client_t *g_ws_client = NULL;
static netstatic_t *g_netstatic = NULL;
/* Per-process network rate calculation state, owned by the report thread.
 * Previously this state lived inside monitoring.c as file-level globals,
 * making the module non-reentrant. Now the caller owns the state and passes
 * it explicitly to monitoring_get_net_info via report_generate. */
static monitoring_net_state_t g_net_state;

/* Detect CR/LF in a string to prevent HTTP header injection via panel-
 * controlled fields (terminal_id, ping_target). Mirrors the helper in
 * config.c and autodiscovery.c. */
static int contains_crlf(const char *s) {
    if (!s) return 0;
    for (const char *p = s; *p; p++) {
        if (*p == '\r' || *p == '\n') return 1;
    }
    return 0;
}

/* Percent-encode a string for safe inclusion in a URL query parameter
 * value. Encodes all characters except unreserved (A-Za-z0-9-_.~) as %XX.
 * Returns the encoded length on success, -1 on buffer overflow. */
static int url_encode_query(const char *in, char *out, size_t out_size) {
    static const char hex[] = "0123456789ABCDEF";
    size_t j = 0;
    for (size_t i = 0; in[i]; i++) {
        unsigned char c = (unsigned char)in[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            if (j + 1 >= out_size) return -1;
            out[j++] = (char)c;
        } else {
            if (j + 3 >= out_size) return -1;
            out[j++] = '%';
            out[j++] = hex[(c >> 4) & 0x0F];
            out[j++] = hex[c & 0x0F];
        }
    }
    out[j] = '\0';
    return (int)j;
}

/**
 * Signal handler for graceful shutdown (SIGINT, SIGTERM).
 *
 * Sets the global running flag to 0 so worker threads can exit their
 * loops. Only async-signal-safe operations are performed here; no
 * logging/printf/syslog calls which are non-reentrant and could
 * deadlock if the signal interrupts the thread currently holding
 * their internal locks.
 *
 * @param sig Received signal number
 */
static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/**
 * Print program usage information and available command-line options.
 *
 * @param prog Program name (usually argv[0])
 */
static void print_usage(const char *prog) {
    printf("Komari Agent (C Language Version) v%s\n", KOMARI_AGENT_C_VERSION_STRING);
    printf("\nUsage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -t, --token <token>       Authentication token\n");
    printf("  -e, --endpoint <url>      Panel server URL\n");
    printf("  -i, --interval <seconds>  Report interval (default: %.1f)\n", DEFAULT_INTERVAL);
    printf("  -d, --dns <server>        Custom DNS server\n");
    printf("  -c, --config <file>       Configuration file path\n");
    printf("  -k, --insecure            Ignore certificate errors\n");
    printf("  -s, --disable-ssh         Disable Web SSH\n");
    printf("  -v, --verbose             Verbose output\n");
    printf("  -h, --help                Show this help message\n");
    printf("\nEnvironment variables:\n");
    printf("  AGENT_TOKEN               Authentication token\n");
    printf("  AGENT_ENDPOINT            Panel server URL\n");
    printf("  AGENT_INTERVAL            Report interval\n");
    printf("  AGENT_CUSTOM_DNS          Custom DNS server\n");
    printf("  AGENT_IGNORE_UNSAFE_CERT  Ignore certificate errors (true/false)\n");
    printf("  AGENT_DISABLE_WEB_SSH     Disable Web SSH (true/false)\n");
}

/* Terminal session context */
typedef struct {
    ws_client_t *ws;           /* Dedicated WebSocket connection for terminal */
    terminal_t *term;          /* Pseudo-terminal */
    volatile bool active;      /* Whether the session is active */
    volatile bool cleanup_done;/* Set by monitor thread after tearing down
                                * resources; main shutdown path inspects this
                                * after pthread_join to know the session memory
                                * is safe to free. */
    bool monitor_started;      /* True once monitor_thread is valid */
    bool detached;             /* True while the WS is gone but the PTY is
                                * kept alive awaiting a re-attach. */
    volatile bool reattach;    /* Set when a new connection re-attaches. */
    char request_id[64];       /* Panel request id (re-attach key) */
    time_t detached_at;        /* When the session was detached. */
    pthread_t monitor_thread;  /* Monitor thread for cleanup */
    pthread_mutex_t term_mutex; /* Protects reads/writes of the term pointer
                                 * across the WS receive thread and the monitor
                                 * thread to prevent use-after-free. */
    char ws_endpoint[512];     /* WebSocket endpoint URL (must match ws lifetime) */
    char extra_query[256];     /* Extra query parameters (must match ws lifetime) */
} terminal_session_t;

/* How long a detached session (WS gone, PTY alive) waits for a re-attach
 * before being torn down; mirrors the Go disconnectedRetention. */
#define TERMINAL_DETACHED_RETENTION_SEC 300

/* Global registry of active terminal sessions so the main shutdown path can
 * signal them to exit and join their monitor threads before tearing down
 * shared resources (g_ws_client, g_netstatic, OpenSSL). Without this, detached
 * monitor threads would be forcibly killed at process exit, leaking the
 * session's WS fd/SSL and orphaning the forkpty-spawned shell. The registry is
 * a fixed-size array because MAX_TERMINAL_SESSIONS is small (8). */
static terminal_session_t *g_sessions[MAX_TERMINAL_SESSIONS];
static pthread_mutex_t g_sessions_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Register a terminal session in the global registry. Returns 0 on success,
 * -1 if the registry is full. Recycles slots whose monitor thread has already
 * finished (cleanup_done=true): the zombie session is joined and freed
 * outside the lock so the slot can be reused by the new session. This keeps
 * the registry from filling up with completed sessions during normal
 * (non-shutdown) operation. */
static int sessions_register(terminal_session_t *session) {
    pthread_mutex_lock(&g_sessions_mutex);
    int rc = -1;
    terminal_session_t *zombie = NULL;
    int zombie_idx = -1;
    for (int i = 0; i < MAX_TERMINAL_SESSIONS; i++) {
        if (g_sessions[i] == NULL) {
            g_sessions[i] = session;
            rc = 0;
            break;
        }
        if (g_sessions[i] != NULL && g_sessions[i]->cleanup_done && zombie == NULL) {
            zombie = g_sessions[i];
            zombie_idx = i;
        }
    }
    if (rc != 0 && zombie != NULL) {
        g_sessions[zombie_idx] = session;
        rc = 0;
    }
    pthread_mutex_unlock(&g_sessions_mutex);

    if (zombie) {
        pthread_join(zombie->monitor_thread, NULL);
        free(zombie);
    }
    return rc;
}

/* Signal every active terminal session to wind down. Called from the main
 * shutdown path before joining worker threads so that monitor threads stop
 * touching shared resources (e.g. OpenSSL) before they are torn down. */
static void sessions_signal_stop(void) {
    pthread_mutex_lock(&g_sessions_mutex);
    for (int i = 0; i < MAX_TERMINAL_SESSIONS; i++) {
        if (g_sessions[i] != NULL) {
            g_sessions[i]->active = false;
        }
    }
    pthread_mutex_unlock(&g_sessions_mutex);
}

/* Join all monitor threads that were started, then free their sessions and
 * clear the registry slots. Called from the main shutdown path after worker
 * threads have joined. Each monitor thread performs its own teardown
 * (terminal_terminate, ws_client_disconnect/destroy, mutex destroy, session
 * release) and only leaves session memory for us to free. */
static void sessions_join_and_cleanup(void) {
    pthread_mutex_lock(&g_sessions_mutex);
    for (int i = 0; i < MAX_TERMINAL_SESSIONS; i++) {
        terminal_session_t *session = g_sessions[i];
        if (session == NULL) continue;
        bool started = session->monitor_started;
        g_sessions[i] = NULL;
        pthread_mutex_unlock(&g_sessions_mutex);

        if (started) {
            pthread_join(session->monitor_thread, NULL);
        }
        free(session);

        pthread_mutex_lock(&g_sessions_mutex);
    }
    pthread_mutex_unlock(&g_sessions_mutex);
}

/* Terminal output callback: send pseudo-terminal output via WebSocket (terminal→WS output thread) */
static void on_terminal_output(terminal_t *term, const char *data, size_t len) {
    terminal_session_t *session = (terminal_session_t *)term->user_data;
    if (session && session->active && session->ws) {
        /* Terminal output travels as binary frames, mirroring the Go
         * reference (terminal.go readOutput uses BinaryMessage). */
        if (ws_client_send_binary(session->ws, data, len) != 0) {
            session->active = false;
        }
    }
    /* While detached (ws == NULL) output is intentionally dropped; the PTY
     * stays alive so a re-attach sees fresh shell state. */
}

/* Terminal WebSocket raw data callback: handle terminal input and resize messages (WS→terminal input thread) */
static void on_terminal_ws_data(ws_client_t *client, const char *data, size_t len) {
    terminal_session_t *session = (terminal_session_t *)ws_client_get_user_data(client);
    if (!session || !session->active) return;

    /* Snapshot the term pointer under the mutex. The monitor thread NULLs
     * session->term before tearing the terminal down, so once we hold a
     * non-NULL local copy the terminal remains valid for the duration of
     * this callback: the monitor thread joins the WS receive thread (which
     * invokes this callback) inside ws_client_disconnect() before calling
     * terminal_destroy(). */
    pthread_mutex_lock(&session->term_mutex);
    terminal_t *term = session->term;
    pthread_mutex_unlock(&session->term_mutex);
    if (!term) return;

    /* JSON control messages (RFC-style payload from the panel), mirroring
     * the Go terminal.go handleInput: {type: resize|input|heartbeat|close}.
     * Non-JSON text and binary frames fall through as raw keyboard input. */
    if (len > 0 && data[0] == '{') {
        cJSON *root = cJSON_Parse(data);
        if (root) {
            cJSON *type = cJSON_GetObjectItem(root, "type");
            if (type && cJSON_IsString(type)) {
                if (strcmp(type->valuestring, "resize") == 0) {
                    cJSON *cols = cJSON_GetObjectItem(root, "cols");
                    cJSON *rows = cJSON_GetObjectItem(root, "rows");
                    if (cols && rows && cJSON_IsNumber(cols) && cJSON_IsNumber(rows)) {
                        terminal_resize(term, cols->valueint, rows->valueint);
                        KOMARI_LOG_DEBUG("[Terminal] Resized to cols=%d rows=%d",
                                         cols->valueint, rows->valueint);
                    }
                    cJSON_Delete(root);
                    return;
                }
                if (strcmp(type->valuestring, "input") == 0) {
                    cJSON *input = cJSON_GetObjectItem(root, "input");
                    if (input && cJSON_IsString(input) && input->valuestring) {
                        terminal_write(term, input->valuestring,
                                       strlen(input->valuestring));
                    }
                    cJSON_Delete(root);
                    return;
                }
                if (strcmp(type->valuestring, "heartbeat") == 0) {
                    /* Keepalive: no action (mirrors the Go empty case). */
                    cJSON_Delete(root);
                    return;
                }
                if (strcmp(type->valuestring, "close") == 0) {
                    KOMARI_LOG_INFO("[Terminal] Close requested by panel");
                    session->active = false;
                    cJSON_Delete(root);
                    return;
                }
            }
            cJSON_Delete(root);
        }
        /* Malformed JSON that starts with '{' is NOT written to the PTY:
         * writing control-message garbage into the shell corrupts the
         * session; the Go reference drops non-JSON text frames, but any
         * '{'-led frame in the wild is a control message. */
        return;
    }

    /* Normal terminal input: write to pseudo-terminal */
    terminal_write(term, data, len);
}

/* Terminal session monitor thread: detect exit and cleanup resources.
 * WS loss only detaches the session (PTY kept alive for
 * TERMINAL_DETACHED_RETENTION_SEC awaiting re-attach, mirroring the Go
 * terminal.go session map); shell exit or the retention timeout performs
 * the actual teardown. */
static void *terminal_monitor_thread(void *arg) {
    terminal_session_t *session = (terminal_session_t *)arg;

    while (session->active) {
        /* Sleep in 1-second slices so the main shutdown path's
         * sessions_signal_stop() is observed within ~1 second instead of
         * blocking pthread_join for the full sleep window. */
        sleep(1);
        if (!session->active) break;

        /* A re-attach clears the detached state and rebinds session->ws. */
        if (session->detached && session->reattach) {
            session->reattach = false;
            session->detached = false;
            session->detached_at = 0;
            continue;
        }

        /* Check if terminal has exited (shell closed). Snapshot term under
         * the mutex because the cleanup path below may NULL it. */
        pthread_mutex_lock(&session->term_mutex);
        terminal_t *term = session->term;
        bool exited = term && !term->running;
        pthread_mutex_unlock(&session->term_mutex);
        if (exited) {
            KOMARI_LOG_INFO("[Terminal] Shell exited, closing session");
            break;
        }

        if (session->detached) {
            /* Retention window elapsed without a re-attach: tear down. */
            if (time(NULL) - session->detached_at >=
                TERMINAL_DETACHED_RETENTION_SEC) {
                KOMARI_LOG_INFO("[Terminal] Detached session %s expired after %d s",
                                session->request_id,
                                TERMINAL_DETACHED_RETENTION_SEC);
                break;
            }
            continue; /* Keep the PTY alive while waiting. */
        }

        /* Check if WebSocket has disconnected */
        if (session->ws) {
            if (!ws_client_is_connected(session->ws)) {
                KOMARI_LOG_INFO("[Terminal] WebSocket disconnected, "
                                "detaching session %s (PTY retained %d s)",
                                session->request_id,
                                TERMINAL_DETACHED_RETENTION_SEC);
                /* Detach: stop the WS but keep the PTY running. The read
                 * thread keeps writing to on_terminal_output, whose
                 * session->active check plus the NULL ws guard below drops
                 * output while detached. */
                session->detached = true;
                session->detached_at = time(NULL);
                ws_client_t *old_ws = session->ws;
                session->ws = NULL;
                ws_client_stop(old_ws);
                ws_client_disconnect(old_ws);
                ws_client_destroy(old_ws);
            }
        }
    }

    session->active = false;

    /* Teardown order (fixes MAJ-13 use-after-free):
     * 1. terminal_terminate() joins the terminal read thread so it stops
     *    calling ws_client_send_text() via on_terminal_output. This must
     *    happen before ws_client_disconnect() frees the SSL/fd resources,
     *    otherwise the read thread could race on client->ssl.
     * 2. ws_client_disconnect() joins the WS receive thread so
     *    on_terminal_ws_data() can no longer touch session->term.
     * 3. terminal_destroy() frees the terminal. Both threads are now joined,
     *    so there is no concurrent access to the terminal struct. Passing
     *    &session->term NULLs the pointer before the free.
     * 4. ws_client_destroy() frees the WS handle. The read thread is already
     *    joined, so it can no longer touch the WS client.
     *
     * The session struct itself is NOT freed here: the main shutdown path
     * joins this thread and then frees the session, so we must leave the
     * memory valid. On the normal (non-shutdown) exit path the session was
     * removed from the global registry before the join, so main will not
     * touch it — but the registry cleanup still owns the free. */
    if (session->term) {
        terminal_terminate(session->term);
    }

    if (session->ws) {
        ws_client_stop(session->ws);
        ws_client_disconnect(session->ws);
    }

    pthread_mutex_lock(&session->term_mutex);
    terminal_destroy(&session->term);
    pthread_mutex_unlock(&session->term_mutex);

    if (session->ws) {
        ws_client_destroy(session->ws);
        session->ws = NULL;
    }

    pthread_mutex_destroy(&session->term_mutex);
    terminal_release_session();
    session->cleanup_done = true;
    return NULL;
}

/* Re-attach a detached terminal session to a fresh WebSocket connection.
 * The PTY keeps running; only the transport is replaced. Returns 0 on
 * success; on failure the session stays detached and the caller may fall
 * back to creating a new session. */
static int terminal_reattach_session(terminal_session_t *session,
                                     const char *token, const char *request_id,
                                     const char *endpoint) {
    KOMARI_LOG_INFO("[Terminal] Re-attaching detached session: %s", request_id);

    /* Reuse the endpoint/query built for the original session. */
    ws_client_config_t ws_config = {0};
    ws_config.disable_compression = g_config.disable_compression;
    ws_config.endpoint = session->ws_endpoint;
    ws_config.token = token;
    ws_config.extra_query = session->extra_query;
    ws_config.ignore_cert = g_config.ignore_unsafe_cert;
    ws_config.max_retries = 1;
    ws_config.reconnect_interval = 1;
    ws_config.keep_endpoint_path = true;

    ws_client_t *ws = ws_client_create(&ws_config);
    if (!ws) return -1;
    ws_client_set_raw_handler(ws, on_terminal_ws_data);
    ws_client_set_user_data(ws, session);

    if (ws_client_connect(ws) != 0) {
        ws_client_destroy(ws);
        KOMARI_LOG_WARN("[Terminal] Re-attach connection failed for %s", request_id);
        return -1;
    }

    /* Swap the transport: the monitor thread is the only other writer of
     * session->ws (it NULLs it when detaching), and it is currently in the
     * detached wait state, so a plain assignment under the mutex suffices. */
    pthread_mutex_lock(&session->term_mutex);
    session->reattach = true;
    pthread_mutex_unlock(&session->term_mutex);

    /* Give the monitor thread up to 2 seconds to observe reattach and
     * clear the detached flag before publishing the new ws. */
    for (int i = 0; i < 20 && session->detached; i++) {
        usleep(100 * 1000);
    }
    session->ws = ws;
    session->detached = false;
    session->detached_at = 0;

    KOMARI_LOG_INFO("[Terminal] Session re-attached: %s", request_id);
    return 0;
}

/* Establish dedicated WebSocket connection for terminal and start pseudo-terminal session */
static int establish_terminal_connection(const char *token, const char *request_id, const char *endpoint) {
    /* Reject CR/LF in request_id to prevent HTTP header injection via the
     * terminal WebSocket handshake query string. The panel-controlled
     * terminal_id flows into the HTTP request line as &id=<request_id>. */
    if (contains_crlf(request_id)) {
        KOMARI_LOG_WARN("[Terminal] Rejected request_id containing CR/LF");
        return -1;
    }

    /* Re-attach fast path (mirrors the Go acquireSession): when a detached
     * session for this request_id still holds a live PTY, bind a fresh WS
     * connection to it instead of spawning another shell. */
    {
        terminal_session_t *target = NULL;
        pthread_mutex_lock(&g_sessions_mutex);
        for (int i = 0; i < MAX_TERMINAL_SESSIONS; i++) {
            terminal_session_t *cand = g_sessions[i];
            if (cand && cand->detached && cand->active &&
                strcmp(cand->request_id, request_id) == 0) {
                target = cand;
                break;
            }
        }
        pthread_mutex_unlock(&g_sessions_mutex);

        if (target) {
            int rc = terminal_reattach_session(target, token, request_id, endpoint);
            if (rc == 0) return 0;
            /* Re-attach failed: fall through and create a fresh session. */
        }
    }

    /* Enforce the concurrent session limit before allocating any resources so
     * that rejected requests do not leak memory or file descriptors. */
    if (terminal_acquire_session() != 0) {
        /* Warning already logged by terminal_acquire_session */
        return -1;
    }

    /* Allocate terminal session context */
    terminal_session_t *session = calloc(1, sizeof(terminal_session_t));
    if (!session) {
        KOMARI_LOG_ERROR("[Terminal] Failed to allocate terminal session");
        terminal_release_session();
        return -1;
    }
    session->active = false;
    snprintf(session->request_id, sizeof(session->request_id), "%s", request_id);

    if (pthread_mutex_init(&session->term_mutex, NULL) != 0) {
        KOMARI_LOG_ERROR("[Terminal] Failed to init term mutex");
        terminal_release_session();
        free(session);
        return -1;
    }

    /* Build WebSocket endpoint URL: convert http(s):// to ws(s):// and append /api/clients/terminal */
    const char *ep = endpoint;
    const char *scheme = "ws://";
    if (strncmp(ep, "http://", 7) == 0) {
        scheme = "ws://";
        ep += 7;
    } else if (strncmp(ep, "https://", 8) == 0) {
        scheme = "wss://";
        ep += 8;
    }

    const char *path_start = strchr(ep, '/');
    if (path_start) {
        size_t host_len = (size_t)(path_start - ep);
        snprintf(session->ws_endpoint, sizeof(session->ws_endpoint),
                 "%s%.*s/api/clients/terminal", scheme, (int)host_len, ep);
    } else {
        snprintf(session->ws_endpoint, sizeof(session->ws_endpoint),
                 "%s%s/api/clients/terminal", scheme, ep);
    }

    /* IDN domain name conversion */
    char ascii_endpoint[512];
    if (idn_convert_url_to_ascii(session->ws_endpoint, ascii_endpoint, sizeof(ascii_endpoint)) == 0) {
        utils_set_string(session->ws_endpoint, sizeof(session->ws_endpoint), ascii_endpoint);
    }

    /* Build extra query parameters. URL-encode request_id before splicing
     * to satisfy the "already-encoded by caller" contract of ws_client and
     * prevent query parameter injection via '&', '=', etc. */
    char encoded_id[256];
    if (url_encode_query(request_id, encoded_id, sizeof(encoded_id)) < 0) {
        KOMARI_LOG_WARN("[Terminal] Failed to URL-encode request_id");
        pthread_mutex_destroy(&session->term_mutex);
        terminal_release_session();
        free(session);
        return -1;
    }
    snprintf(session->extra_query, sizeof(session->extra_query), "&id=%s", encoded_id);

    /* Create WebSocket client */
    ws_client_config_t ws_config = {0};
    ws_config.disable_compression = g_config.disable_compression;
    ws_config.endpoint = session->ws_endpoint;
    ws_config.token = token;
    ws_config.extra_query = session->extra_query;
    ws_config.ignore_cert = g_config.ignore_unsafe_cert;
    ws_config.max_retries = 1;
    ws_config.reconnect_interval = 1;
    /* Keep the /api/clients/terminal path built above: ws_client_connect
     * must not rewrite this dedicated endpoint to the report/RPC path. */
    ws_config.keep_endpoint_path = true;

    session->ws = ws_client_create(&ws_config);
    if (!session->ws) {
        KOMARI_LOG_ERROR("[Terminal] Failed to create WebSocket client");
        pthread_mutex_destroy(&session->term_mutex);
        terminal_release_session();
        free(session);
        return -1;
    }

    /* Set raw data callback and user data */
    ws_client_set_raw_handler(session->ws, on_terminal_ws_data);
    ws_client_set_user_data(session->ws, session);

    /* Connect WebSocket */
    if (ws_client_connect(session->ws) != 0) {
        KOMARI_LOG_ERROR("[Terminal] Failed to connect WebSocket for %s", request_id);
        ws_client_destroy(session->ws);
        pthread_mutex_destroy(&session->term_mutex);
        terminal_release_session();
        free(session);
        return -1;
    }

    /* Create pseudo-terminal (default 80x24, can be adjusted later via resize) */
    session->term = terminal_create(80, 24);
    if (!session->term) {
        KOMARI_LOG_ERROR("[Terminal] Failed to create terminal");
        ws_client_stop(session->ws);
        ws_client_disconnect(session->ws);
        ws_client_destroy(session->ws);
        pthread_mutex_destroy(&session->term_mutex);
        terminal_release_session();
        free(session);
        return -1;
    }

    /* Set terminal output callback and user data */
    terminal_set_user_data(session->term, session);
    terminal_set_output_cb(session->term, on_terminal_output);

    /* Start terminal (forkpty + shell + read thread) */
    if (terminal_start(session->term, NULL) != 0) {
        KOMARI_LOG_ERROR("[Terminal] Failed to start terminal");
        /* Disconnect WS first (joins recv thread) so on_terminal_ws_data
         * cannot race with terminal_destroy. */
        ws_client_stop(session->ws);
        ws_client_disconnect(session->ws);
        terminal_destroy(&session->term);
        ws_client_destroy(session->ws);
        pthread_mutex_destroy(&session->term_mutex);
        terminal_release_session();
        free(session);
        return -1;
    }

    session->active = true;
    session->cleanup_done = false;
    session->monitor_started = false;

    /* Register the session before starting the monitor thread so the shutdown
     * path always sees a consistent registry state. If register fails the
     * registry is full of non-zombie sessions (should not happen because
     * terminal_acquire_session enforces the same limit, but guard anyway). */
    if (sessions_register(session) != 0) {
        KOMARI_LOG_ERROR("[Terminal] Session registry full");
        session->active = false;
        terminal_terminate(session->term);
        ws_client_stop(session->ws);
        ws_client_disconnect(session->ws);
        terminal_destroy(&session->term);
        ws_client_destroy(session->ws);
        pthread_mutex_destroy(&session->term_mutex);
        terminal_release_session();
        free(session);
        return -1;
    }

    /* Start monitor thread (joinable; main shutdown path joins it via
     * sessions_join_and_cleanup so it is never forcibly killed mid-cleanup). */
    if (pthread_create(&session->monitor_thread, NULL, terminal_monitor_thread, session) != 0) {
        KOMARI_LOG_ERROR("[Terminal] Failed to create monitor thread");
        session->active = false;
        /* Same teardown order as the monitor thread: terminate terminal first
         * (joins read thread so it stops touching ws), then disconnect WS
         * (joins recv thread so it stops touching term), then free both. */
        terminal_terminate(session->term);
        ws_client_stop(session->ws);
        ws_client_disconnect(session->ws);
        terminal_destroy(&session->term);
        ws_client_destroy(session->ws);
        pthread_mutex_destroy(&session->term_mutex);
        terminal_release_session();
        /* Remove from registry since monitor thread never started. */
        pthread_mutex_lock(&g_sessions_mutex);
        for (int i = 0; i < MAX_TERMINAL_SESSIONS; i++) {
            if (g_sessions[i] == session) {
                g_sessions[i] = NULL;
                break;
            }
        }
        pthread_mutex_unlock(&g_sessions_mutex);
        free(session);
        return -1;
    }
    session->monitor_started = true;

    KOMARI_LOG_INFO("[Terminal] Session established: %s", request_id);
    return 0;
}


/* Upper bound for captured exec output uploaded back to the panel. The v2
 * result payload allows up to 64 KiB; the escaped form can exceed the raw
 * bytes, so the raw capture stays well below it. */
#define EXEC_OUTPUT_MAX (32 * 1024)

/**
 * Handle incoming WebSocket messages from the panel.
 *
 * Dispatches terminal requests (Web SSH), exec task commands and ping
 * tasks to their respective handlers, uploading results back to the
 * panel via the report module.
 *
 * @param client WebSocket client that received the message
 * @param msg    Parsed WebSocket message structure
 */
static void handle_ws_message(ws_client_t *client, const ws_message_t *msg) {
    (void)client;
    if (strcmp(msg->message, "terminal") == 0 || msg->terminal_id[0] != '\0') {
        if (!g_config.disable_web_ssh) {
            KOMARI_LOG_INFO("[Terminal] Received terminal request: %s", msg->terminal_id);
            establish_terminal_connection(g_config.token, msg->terminal_id, g_config.endpoint);
        } else {
            KOMARI_LOG_INFO("[Terminal] Web SSH is disabled");
        }
    } else if (strcmp(msg->message, "exec") == 0) {
        char output[EXEC_OUTPUT_MAX] = "";
        int exit_code = 0;

        /* Mirror the Go reference (server/task.go): remote commands run under
         * "sh -s" with the command text on stdin, so panels can send full
         * shell syntax (pipes, redirects, globs). The same disable_web_ssh
         * switch that gates the terminal also gates RCE, matching the Go
         * behavior where disabled remote control answers with a synthetic
         * "Remote control is disabled." result (exit code -1). */
        if (g_config.disable_web_ssh) {
            KOMARI_LOG_INFO("[Task] Remote control is disabled, rejecting exec (Task ID: %s)",
                            msg->exec_task_id);
            report_upload_task_result(&g_config, msg->exec_task_id,
                                      "Remote control is disabled.", -1,
                                      utils_get_current_timestamp());
            return;
        }

        if (msg->exec_command[0] == '\0') {
            KOMARI_LOG_WARN("[Task] No command provided (Task ID: %s)", msg->exec_task_id);
            report_upload_task_result(&g_config, msg->exec_task_id,
                                      "No command provided", 0,
                                      utils_get_current_timestamp());
            return;
        }

        /* Pre-execution guard on the raw command text: reject references to
         * sensitive virtual filesystems and path traversal to shrink the
         * attack surface (kept from the previous C-only hardening). */
        if (strncmp(msg->exec_command, "/proc/", 6) == 0 ||
            strncmp(msg->exec_command, "/sys/", 5) == 0 ||
            strstr(msg->exec_command, "..") != NULL) {
            KOMARI_LOG_WARN("[Task] Rejected exec touching restricted path (Task ID: %s)",
                            msg->exec_task_id);
            report_upload_task_result(&g_config, msg->exec_task_id,
                                      "exec: command path rejected", 126,
                                      utils_get_current_timestamp());
            return;
        }

        char *argv[] = {"sh", "-s", NULL};
        /* Log only at DEBUG level to avoid leaking sensitive command text
         * into syslog. */
        KOMARI_LOG_DEBUG("[Task] Executing via sh -s (Task ID: %s)", msg->exec_task_id);
        if (utils_exec_command_argv_stdin(argv, msg->exec_command,
                                          strlen(msg->exec_command),
                                          output, sizeof(output), &exit_code) == 0) {
            report_upload_task_result(&g_config, msg->exec_task_id, output, exit_code,
                                       utils_get_current_timestamp());
        } else {
            /* fork()/pipe() failure inside the exec helper: report a
             * synthetic failure result (exit code 127) so the panel's
             * task does not hang. */
            KOMARI_LOG_ERROR("[Task] Failed to execute command (Task ID: %s)",
                             msg->exec_task_id);
            report_upload_task_result(&g_config, msg->exec_task_id,
                                      "exec: failed to execute command", 127,
                                      utils_get_current_timestamp());
        }
    } else if (strcmp(msg->message, "ping") == 0 || msg->ping_type[0] != '\0') {
        KOMARI_LOG_INFO("[Ping] Received ping request: %s (%s) Task ID: %u",
                        msg->ping_target, msg->ping_type, msg->ping_task_id);
        
        if (msg->ping_task_id > 0 && msg->ping_type[0] != '\0' && msg->ping_target[0] != '\0') {
            ping_task_config_t ping_config;
            memset(&ping_config, 0, sizeof(ping_config));
            ping_config.timeout_ms = PING_DEFAULT_TIMEOUT_MS;
            ping_config.high_latency_threshold_ms = PING_HIGH_LATENCY_THRESHOLD_MS;
            ping_config.high_latency_retries = PING_HIGH_LATENCY_RETRIES;
            /* Forward the agent's ignore_unsafe_cert setting so HTTPS ping
             * targets verify certificates by default. */
            ping_config.ignore_cert = g_config.ignore_unsafe_cert ? 1 : 0;
            if (g_config.custom_dns[0] != '\0') {
                strncpy(ping_config.custom_dns, g_config.custom_dns, sizeof(ping_config.custom_dns) - 1);
            }
            
            ping_task_result_t ping_result;
            int ret = ping_task_execute(msg->ping_target, msg->ping_type, &ping_config, &ping_result);
            if (ret == 0) {
                ping_result.task_id = msg->ping_task_id;
                report_upload_ping_result(&g_config, ping_result.task_id,
                                          ping_result.ping_type, ping_result.result,
                                          (uint64_t)ping_result.finished_at);
            } else {
                report_upload_ping_result(&g_config, msg->ping_task_id,
                                          msg->ping_type, -1,
                                          (uint64_t)time(NULL));
            }
        }
    }
}

/* ====== File manager dispatch (agent.file) ====== */

/* File-operation worker: runs the op synchronously and reports the result.
 * Takes ownership of params (frees it). Executes with the filemgr
 * concurrency gate held (8 concurrent ops max, mirroring the Go
 * maxFileStreamOperations). */
static void *filemgr_worker(void *arg) {
    cJSON *params = (cJSON *)arg;

    /* Handler context is process-global: use the main WS client only for
     * logging; the result upload is a plain HTTP POST. */
    cJSON *result = filemgr_execute(&g_config, params);
    cJSON_Delete(params);
    if (result) {
        filemgr_upload_result(&g_config, result);
    }
    filemgr_release();
    return NULL;
}

/* File params callback invoked from the WS recv thread (or the fallback
 * channel). Detaches a bounded worker so the recv thread never blocks. */
static void handle_file_params(ws_client_t *client, cJSON *params) {
    (void)client;
    if (!filemgr_allowed(&g_config)) {
        KOMARI_LOG_INFO("[FileMgr] Web control is disabled, dropping agent.file");
        cJSON_Delete(params);
        return;
    }
    if (filemgr_try_acquire() != 0) {
        KOMARI_LOG_WARN("[FileMgr] Concurrency limit (%d) reached, dropping op",
                        FILEMGR_MAX_CONCURRENT);
        cJSON_Delete(params);
        return;
    }
    pthread_t tid;
    if (pthread_create(&tid, NULL, filemgr_worker, params) != 0) {
        KOMARI_LOG_ERROR("[FileMgr] Failed to spawn worker");
        cJSON_Delete(params);
        filemgr_release();
        return;
    }
    pthread_detach(tid);
}

/* ====== Monthly traffic hook (netstatic integration) ====== */

/* Fill the monthly (tx, rx) totals across all filtered interfaces from the
 * netstatic sampler, mirroring the Go net.go accumulation over
 * GetTotalTrafficBetween(resetDay, now). */
static int main_monthly_traffic(uint64_t *tx, uint64_t *rx) {
    if (!g_netstatic) return -1;

    uint64_t total_tx = 0, total_rx = 0;
    char ifaces[64][32];
    int n = monitoring_list_interfaces(ifaces, 64);
    if (n <= 0) return -1;

    for (int i = 0; i < n; i++) {
        uint64_t if_tx = 0, if_rx = 0;
        if (netstatic_get_monthly_traffic(g_netstatic, ifaces[i],
                                          &if_tx, &if_rx) != 0) {
            return -1;
        }
        if (if_tx > UINT64_MAX - total_tx) total_tx = UINT64_MAX;
        else total_tx += if_tx;
        if (if_rx > UINT64_MAX - total_rx) total_rx = UINT64_MAX;
        else total_rx += if_rx;
    }
    *tx = total_tx;
    *rx = total_rx;
    return 0;
}

/* Strong definition overriding the weak default in report.c. */
int report_monthly_traffic_hook(uint64_t *tx, uint64_t *rx) {
    return main_monthly_traffic(tx, rx);
}

/* ====== POST fallback (agent.pull) ====== */

/* Dispatch a v2 event pulled from the fallback channel. Mirrors the
 * method-to-ws_message_t mapping used by ws_handle_v2_event so the same
 * handler (handle_ws_message) executes exec/ping/terminal identically on
 * both channels.
 *
 * @param event_id Numeric event ID for ACK accumulation (0 = no ACK)
 * @param method   JSON-RPC method name
 * @param params   Event params object (may be NULL)
 * @return 1 when the event was handled (or recognized as a no-op), 0 when
 *         the method is unknown (not ACKed, like the Go reference). */
static int fallback_dispatch_event(const char *event_id, const char *method,
                                   const cJSON *params) {
    ws_message_t msg = {0};

    if (strcmp(method, AGENT_EXEC) == 0) {
        strncpy(msg.message, "exec", sizeof(msg.message) - 1);
        cJSON *item = params ? cJSON_GetObjectItem(params, "task_id") : NULL;
        if (item && cJSON_IsString(item) && item->valuestring) {
            strncpy(msg.exec_task_id, item->valuestring, sizeof(msg.exec_task_id) - 1);
        }
        item = params ? cJSON_GetObjectItem(params, "command") : NULL;
        if (item && cJSON_IsString(item) && item->valuestring) {
            strncpy(msg.exec_command, item->valuestring, sizeof(msg.exec_command) - 1);
        }
        handle_ws_message(NULL, &msg);
        return 1;
    }
    if (strcmp(method, AGENT_PING) == 0) {
        strncpy(msg.message, "ping", sizeof(msg.message) - 1);
        cJSON *item = params ? cJSON_GetObjectItem(params, "ping_task_id") : NULL;
        if (item && cJSON_IsNumber(item)) {
            msg.ping_task_id = (uint32_t)item->valuedouble;
        }
        item = params ? cJSON_GetObjectItem(params, "ping_type") : NULL;
        if (item && cJSON_IsString(item) && item->valuestring) {
            strncpy(msg.ping_type, item->valuestring, sizeof(msg.ping_type) - 1);
        }
        item = params ? cJSON_GetObjectItem(params, "ping_target") : NULL;
        if (item && cJSON_IsString(item) && item->valuestring) {
            strncpy(msg.ping_target, item->valuestring, sizeof(msg.ping_target) - 1);
        }
        if (contains_crlf(msg.ping_target)) {
            KOMARI_LOG_WARN("[Fallback] Rejected ping_target containing CR/LF");
        } else {
            handle_ws_message(NULL, &msg);
        }
        return 1;
    }
    if (strcmp(method, AGENT_TERMINAL_REQUEST) == 0) {
        cJSON *item = params ? cJSON_GetObjectItem(params, "request_id") : NULL;
        if (item && cJSON_IsString(item) && item->valuestring) {
            strncpy(msg.terminal_id, item->valuestring, sizeof(msg.terminal_id) - 1);
        }
        if (contains_crlf(msg.terminal_id)) {
            KOMARI_LOG_WARN("[Fallback] Rejected terminal_id containing CR/LF");
        } else {
            handle_ws_message(NULL, &msg);
        }
        return 1;
    }
    if (strcmp(method, AGENT_FILE) == 0) {
        /* File ops over the fallback channel go through the same handler;
         * handle_file_params owns the params copy we pass it. */
        cJSON *copy = params ? cJSON_Duplicate(params, 1) : NULL;
        if (copy) {
            handle_file_params(NULL, copy);
        }
        return 1;
    }
    if (strcmp(method, AGENT_MESSAGE) == 0 || strcmp(method, AGENT_EVENT) == 0) {
        KOMARI_LOG_INFO("[Fallback] Received %s event", method);
        return 1;
    }
    KOMARI_LOG_WARN("[Fallback] Unknown event method: %s", method);
    return 0;
}

/* Extract fields of each event object {id, method, params} and dispatch it.
 * Returns 1 when the event should be ACKed. */
static int fallback_process_event(const cJSON *ev) {
    if (!ev || !cJSON_IsObject(ev)) return 0;

    cJSON *method = cJSON_GetObjectItem(ev, "method");
    if (!method || !cJSON_IsString(method) || !method->valuestring) return 0;

    cJSON *params = cJSON_GetObjectItem(ev, "params");
    cJSON *id = cJSON_GetObjectItem(ev, "id");

    /* Dedup by string ID via the shared v2 state so an event delivered both
     * over WS and the fallback channel executes exactly once. */
    char id_buf[32] = {0};
    const char *id_str = NULL;
    int ack_id = 0;
    if (id && cJSON_IsString(id) && id->valuestring && id->valuestring[0]) {
        id_str = id->valuestring;
        char *endp = NULL;
        long val = strtol(id->valuestring, &endp, 10);
        if (endp != id->valuestring && val > 0) ack_id = (int)val;
    } else if (id && cJSON_IsNumber(id)) {
        long val = (long)id->valuedouble;
        if (val > 0) {
            ack_id = (int)val;
            if (snprintf(id_buf, sizeof(id_buf), "%ld", val) > 0) id_str = id_buf;
        }
    }

    if (id_str && v2_is_event_seen(ws_client_get_v2_state(g_ws_client), id_str)) {
        return ack_id > 0; /* Already executed: ACK without re-running. */
    }
    if (id_str &&
        v2_add_seen_event(ws_client_get_v2_state(g_ws_client), id_str) != 0) {
        KOMARI_LOG_WARN("[Fallback] Failed to record seen event id: %s", id_str);
    }

    int handled = fallback_dispatch_event(id_str, method->valuestring, params);
    return (handled && ack_id > 0) ? ack_id : (handled ? -1 : 0);
}

/* Process a response body's events; ACKs accumulate in the v2 state. */
static void fallback_process_response_events(const cJSON *response) {
    const cJSON *events = NULL;
    if (fallback_extract_events(response, &events) <= 0) return;
    const cJSON *ev;
    cJSON_ArrayForEach(ev, events) {
        fallback_process_event(ev);
    }
}

/* POST fallback loop, entered when WS retries are exhausted. Runs until a
 * WS reconnect succeeds or g_running clears, mirroring the Go reference
 * (server/websocket.go runPostFallback): report ticker at interval seconds,
 * pull loop polling without pause on success, reconnect attempt every
 * reconnect_interval seconds. */
static void run_post_fallback(void) {
    KOMARI_LOG_WARN("[Fallback] Entering HTTP POST fallback mode");

    time_t last_report = 0;

    while (g_running) {
        /* Reconnect attempt (bounded by reconnect_interval seconds of pull
         * activity below). */
        if (ws_client_connect(g_ws_client) == 0) {
            KOMARI_LOG_INFO("[Fallback] WebSocket reconnected, leaving fallback mode");
            return;
        }

        /* Pull loop: poll continuously for reconnect_interval seconds. */
        time_t pull_deadline = time(NULL) + g_config.reconnect_interval;
        while (g_running && time(NULL) < pull_deadline) {
            int ack_buf[V2_ACK_IDS_MAX];
            int ack_count = 0;
            v2_snapshot_ack_ids(ws_client_get_v2_state(g_ws_client), ack_buf,
                                (int)(sizeof(ack_buf) / sizeof(ack_buf[0])),
                                &ack_count);

            char *pull_req = NULL;
            if (fallback_build_pull_request((long)time(NULL),
                                            ack_count > 0 ? ack_buf : NULL,
                                            ack_count, &pull_req) != 0) {
                break;
            }

            cJSON *resp = NULL;
            if (fallback_post_rpc(&g_config, pull_req, !g_config.disable_compression,
                                  0, &resp) == 0) {
                /* Success: clear the ACKs that were carried, then handle
                 * any returned events (their ACKs accumulate for the next
                 * request, mirroring the Go snapshot/clear order). */
                v2_clear_acks(ws_client_get_v2_state(g_ws_client));
                fallback_process_response_events(resp);
            }
            cJSON_Delete(resp);
            free(pull_req);

            /* Periodic report over POST while disconnected. */
            time_t now = time(NULL);
            if (now - last_report >= (time_t)g_config.interval) {
                char report_buf[8192];
                report_status_metrics_t metrics;
                memset(&metrics, 0, sizeof(metrics));
                int rlen = report_generate_v2_with_acks_ex(
                    &g_config, &g_net_state, report_buf, sizeof(report_buf),
                    NULL, 0, &metrics);
                if (rlen > 0) {
                    /* Wrap the report body into a request with ACKs. */
                    /* report_generate_v2_with_acks_ex already emits the
                     * request envelope including ack_event_ids; reuse it
                     * directly as the POST body. */
                    char *body = malloc((size_t)rlen + 1);
                    if (body) {
                        memcpy(body, report_buf, (size_t)rlen);
                        body[rlen] = '\0';
                        cJSON *report_resp = NULL;
                        if (fallback_post_rpc(&g_config, body,
                                              !g_config.disable_compression,
                                              0, &report_resp) == 0) {
                            v2_clear_acks(ws_client_get_v2_state(g_ws_client));
                            fallback_process_response_events(report_resp);
                            report_write_status_file(&g_config, &metrics, false);
                        }
                        cJSON_Delete(report_resp);
                        free(body);
                    }
                }
                last_report = now;
            }
        }
    }
}

/**
 * Reporting thread: maintains the WebSocket connection and periodically
 * sends status reports and basic info to the panel.
 *
 * All payloads use the JSON-RPC 2.0 (v2) envelope, mirroring the Go
 * reference implementation (server/websocket.go, EstablishWebSocket
 * Connection). Reports carry the pending ACK event IDs so the server can
 * stop retransmitting processed events.
 *
 * @param arg Unused thread argument
 * @return NULL
 */
static void *report_thread(void *arg) {
    (void)arg;

    char report_buf[8192];
    time_t last_basic_info = 0;

    while (g_running) {
        bool connected = ws_client_is_connected(g_ws_client);

        if (!connected) {
            KOMARI_LOG_INFO("[WebSocket] Connecting to %s...", g_config.endpoint);
            /* Refresh the LuCI status file with connected=false so the
             * dashboard reflects the outage instead of stale metrics from
             * the last healthy tick. */
            report_write_status_file(&g_config, NULL, false);

            int retries = 0;
            while (retries < g_config.max_retries && g_running) {
                if (ws_client_connect(g_ws_client) == 0) {
                    KOMARI_LOG_INFO("[WebSocket] Connected successfully");
                    break;
                }

                retries++;
                KOMARI_LOG_WARN("[WebSocket] Connection failed, retry %d/%d", retries, g_config.max_retries);
                /* Sleep in 1-second slices so the thread observes g_running
                 * promptly during shutdown. Without this, a 5-second
                 * reconnect_interval would block pthread_join in the cleanup
                 * path for the full duration, exceeding procd's 5-second
                 * stop timeout and forcing SIGKILL (which leaks fd/SSL). */
                for (int i = 0; i < g_config.reconnect_interval && g_running; i++) {
                    sleep(1);
                }
            }

            if (retries >= g_config.max_retries) {
                /* WS retries exhausted: keep reporting and receiving events
                 * over HTTP POST (agent.report / agent.pull) until the
                 * connection recovers, mirroring the Go POST fallback. The
                 * outer loop resumes WS attempts when the fallback exits. */
                run_post_fallback();
                continue;
            }
        }

        /* Snapshot the pending ACK event IDs and include them in the report
         * payload so the server can stop retransmitting events the agent has
         * already processed. The snapshot is taken under the v2 state mutex,
         * so it is safe even if the recv thread is concurrently adding new
         * ACKs via ws_handle_v2_event. */
        /* Size the snapshot buffer to V2_ACK_IDS_MAX so the full pending
         * ACK set is reported in a single cycle. A 256-entry buffer silently
         * truncated to 256 while v2_clear_acks removed all 1024,
         * dropping 768 unreported ACKs and causing the server to retransmit
         * those events every cycle. 4 KB of stack is acceptable for a 1 Hz
         * report path. */
        _Static_assert(V2_ACK_IDS_MAX >= V2_ACK_SNAPSHOT_RECOMMENDED,
                       "snapshot buffer smaller than recommended capacity");
        int ack_buf[V2_ACK_IDS_MAX];
        int ack_count = 0;
        int len;
        report_status_metrics_t status_metrics;
        memset(&status_metrics, 0, sizeof(status_metrics));

        v2_snapshot_ack_ids(ws_client_get_v2_state(g_ws_client), ack_buf,
                            (int)(sizeof(ack_buf) / sizeof(ack_buf[0])),
                            &ack_count);
        len = report_generate_v2_with_acks_ex(&g_config, &g_net_state, report_buf,
                                              sizeof(report_buf),
                                              ack_count > 0 ? ack_buf : NULL,
                                              ack_count, &status_metrics);

        bool is_connected = ws_client_is_connected(g_ws_client);

        if (len > 0 && is_connected) {
            if (ws_client_send_text(g_ws_client, report_buf, len) != 0) {
                KOMARI_LOG_ERROR("[WebSocket] Failed to send data");
                ws_client_disconnect(g_ws_client);
            } else if (ack_count > 0) {
                /* Report sent successfully: clear the ACK IDs that were
                 * included in the snapshot so they are not re-sent next cycle.
                 * New ACKs added between snapshot and clear (by the recv
                 * thread processing fresh events) are also cleared; the
                 * server will retransmit those events and the dedup logic in
                 * ws_handle_v2_event will skip re-execution while still
                 * re-ACKing them. This matches the simple clear-all semantic
                 * of v2_clear_acks (the C v2 interface does not expose a
                 * "remove only these IDs" operation). */
                v2_clear_acks(ws_client_get_v2_state(g_ws_client));
            }
        }

        /* Publish this tick's metrics for the LuCI status page. Written even
         * when the send failed (with the actual connection state) so the
         * dashboard never shows data older than one report interval. */
        if (len > 0) {
            report_write_status_file(&g_config, &status_metrics, is_connected);
        }

        time_t now = time(NULL);
        if (now - last_basic_info >= g_config.info_report_interval * 60) {
            /* Basic info goes out via HTTP POST to the v2 RPC endpoint,
             * mirroring the Go reference (server/basicInfo.go). It does not
             * depend on the WebSocket being connected. */
            int bi_len = report_generate_basic_info_v2(&g_config, report_buf,
                                                       sizeof(report_buf));
            if (bi_len > 0 &&
                report_upload_basic_info(&g_config, report_buf, (size_t)bi_len) != 0) {
                KOMARI_LOG_WARN("[Report] Basic info upload failed; will retry next cycle");
            }
            last_basic_info = now;
        }

        /* Sleep in 1-second slices so the thread observes g_running
         * promptly during shutdown. Without this, a large interval
         * (e.g. 60s) would delay pthread_join in the cleanup path for
         * up to that full duration. */
        for (int i = 0; i < (int)g_config.interval && g_running; i++) {
            sleep(1);
        }
    }

    return NULL;
}

/**
 * Heartbeat thread: sends a WebSocket ping every 30 seconds to keep the
 * connection alive.
 *
 * @param arg Unused thread argument
 * @return NULL
 */
static void *heartbeat_thread(void *arg) {
    (void)arg;

    /* g_ws_client is assigned once in main() before this thread is created and
     * kept alive until after pthread_join returns; the NULL check is therefore
     * redundant. Check g_running only so the loop winds down promptly on
     * SIGTERM/SIGINT. */
    while (g_running) {
        /* ws_client_is_connected takes the state mutex internally so the
         * read is synchronized with writers in websocket.c. */
        bool connected = ws_client_is_connected(g_ws_client);

        if (connected) {
            if (ws_client_send_ping(g_ws_client) != 0) {
                /* Use the project logger so the message is subject to log
                 * level control and written to the log file in daemon mode;
                 * printf bypasses both and would be lost under procd. */
                KOMARI_LOG_WARN("[WebSocket] Heartbeat failed");
                /* Flag-only stop (no fd/SSL teardown): marks the connection
                 * as closed so the report thread's next is_connected() check
                 * drives a reconnect instead of sending into a dead
                 * connection. Repeated failures previously only logged and
                 * left a black-holed connection in place. */
                ws_client_stop(g_ws_client);
            }
        }
        /* Sleep in 1-second slices so the thread observes g_running
         * promptly during shutdown instead of blocking for the full
         * 30-second heartbeat interval. This ensures pthread_join in
         * the cleanup path returns within ~1 second rather than 30. */
        for (int i = 0; i < 30 && g_running; i++) {
            sleep(1);
        }
    }

    return NULL;
}

/**
 * Program entry point.
 *
 * Parses command-line arguments, loads configuration from environment,
 * file and UCI in order, performs auto-discovery registration if a key
 * is provided, then creates the WebSocket client and starts the
 * reporting, heartbeat and update-checker threads.
 *
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, non-zero on failure
 */
int main(int argc, char *argv[]) {
    /* OpenSSL 1.1.0+ initializes itself automatically; no explicit
     * SSL_library_init / SSL_load_error_strings / OpenSSL_add_all_algorithms
     * calls are needed. The project requires OpenSSL >= 1.1.0 (see
     * cmake/Dependencies.cmake), so the 1.0.2 init path was removed. */

    config_init(&g_config);
    
    static struct option long_options[] = {
        {"token",       required_argument, 0, 't'},
        {"endpoint",    required_argument, 0, 'e'},
        {"interval",    required_argument, 0, 'i'},
        {"dns",         required_argument, 0, 'd'},
        {"config",      required_argument, 0, 'c'},
        {"insecure",    no_argument,       0, 'k'},
        {"disable-ssh", no_argument,       0, 's'},
        {"verbose",     no_argument,       0, 'v'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    /* Command-line values are saved to separate buffers and applied after all
     * other configuration sources are loaded. This guarantees command-line
     * arguments always win over UCI/JSON/env, matching the priority order:
     * command-line > env > UCI > JSON > defaults. Without this, later loaders
     * (e.g. UCI emitting an empty token) would silently overwrite values
     * explicitly passed on the command line. */
    char cli_token[MAX_TOKEN_LEN] = {0};
    char cli_endpoint[MAX_ENDPOINT_LEN] = {0};
    char cli_custom_dns[MAX_DNS_LEN] = {0};
    char cli_config_file[MAX_CONFIG_FILE_LEN] = {0};
    double cli_interval = 0.0;
    bool cli_set_token = false;
    bool cli_set_endpoint = false;
    bool cli_set_interval = false;
    bool cli_set_custom_dns = false;
    bool cli_set_config_file = false;
    bool cli_set_insecure = false;
    bool cli_set_disable_ssh = false;
    bool verbose = false;

    int opt;
    while ((opt = getopt_long(argc, argv, "t:e:i:d:c:ksvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                utils_set_string(cli_token, sizeof(cli_token), optarg);
                cli_set_token = true;
                break;
            case 'e':
                utils_set_string(cli_endpoint, sizeof(cli_endpoint), optarg);
                cli_set_endpoint = true;
                break;
            case 'i':
                cli_interval = atof(optarg);
                cli_set_interval = true;
                break;
            case 'd':
                utils_set_string(cli_custom_dns, sizeof(cli_custom_dns), optarg);
                cli_set_custom_dns = true;
                break;
            case 'c':
                utils_set_string(cli_config_file, sizeof(cli_config_file), optarg);
                cli_set_config_file = true;
                break;
            case 'k':
                cli_set_insecure = true;
                break;
            case 's':
                cli_set_disable_ssh = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Initialize the logger before any configuration source is loaded so
     * warnings from the loaders and config_validate() are actually emitted.
     * Previously logger_init was never called, leaving the logger in its
     * zero-initialized default state (no stdout, no syslog) and turning
     * every KOMARI_LOG_* call in the program into a silent no-op. Output
     * goes to stdout, which procd redirects to the system log via
     * procd_set_param stdout; -v/--verbose lowers the threshold to DEBUG. */
    logger_config_t log_cfg;
    memset(&log_cfg, 0, sizeof(log_cfg));
    log_cfg.level = verbose ? LOG_LEVEL_DEBUG : LOG_LEVEL_INFO;
    log_cfg.use_stdout = true;
    log_cfg.use_syslog = false;
    log_cfg.tag = NULL;
    logger_init(&log_cfg);

    /* Resolve the JSON config file path: command-line -c takes priority over
     * the AGENT_CONFIG_FILE environment variable. Both must be resolved before
     * loading JSON so the correct file is read. */
    if (cli_set_config_file) {
        utils_set_string(g_config.config_file, sizeof(g_config.config_file), cli_config_file);
    } else {
        char *env_cfg = getenv("AGENT_CONFIG_FILE");
        if (env_cfg && env_cfg[0] != '\0') {
            utils_set_string(g_config.config_file, sizeof(g_config.config_file), env_cfg);
        }
    }

    /* Load configuration sources in priority order from lowest to highest:
     * JSON file -> UCI -> env. Defaults are already set by config_init.
     * Command-line values are applied last to guarantee they win. */
    if (g_config.config_file[0] != '\0') {
        config_load_from_file(&g_config, g_config.config_file);
    }

    config_load_from_uci(&g_config);

    config_load_from_env(&g_config);

    /* Apply command-line arguments last so they take precedence over every
     * other source. Also restore the config_file field, which
     * config_load_from_env may have overwritten with AGENT_CONFIG_FILE even
     * though JSON was already loaded from the command-line path. */
    if (cli_set_token) {
        utils_set_string(g_config.token, sizeof(g_config.token), cli_token);
    }
    if (cli_set_endpoint) {
        utils_set_string(g_config.endpoint, sizeof(g_config.endpoint), cli_endpoint);
    }
    if (cli_set_interval) {
        g_config.interval = cli_interval;
    }
    if (cli_set_custom_dns) {
        utils_set_string(g_config.custom_dns, sizeof(g_config.custom_dns), cli_custom_dns);
    }
    if (cli_set_insecure) {
        g_config.ignore_unsafe_cert = true;
    }
    if (cli_set_disable_ssh) {
        g_config.disable_web_ssh = true;
    }
    if (cli_set_config_file) {
        utils_set_string(g_config.config_file, sizeof(g_config.config_file), cli_config_file);
    }

    /* Validate the merged configuration before any subsystem consumes it.
     * config_validate repairs out-of-range numeric fields (interval,
     * reconnect_interval, etc.), strips CR/LF from the endpoint to prevent
     * HTTP header injection, and logs missing required fields (token,
     * endpoint). It never aborts the process; the explicit checks below
     * still decide whether the agent can start. */
    config_validate(&g_config);

    /* Apply the NIC / mount point filters to the monitoring module so the
     * configured include_nics / exclude_nics / include_mountpoints options
     * take effect (they were previously loaded but never consumed). */
    monitoring_set_nic_filters(g_config.include_nics, g_config.exclude_nics);
    monitoring_set_mountpoint_filter(g_config.include_mountpoints);
    monitoring_set_host_proc(g_config.host_proc);

    /* Ignore SIGPIPE to prevent process termination on broken pipe (mirrors Go runtime default).
     * Network write operations (send/SSL_write) will return EPIPE/EPIPE error instead. */
    signal(SIGPIPE, SIG_IGN);

    /* Auto-discovery: if auto_discovery_key is configured and token is empty, attempt auto-registration */
    if (g_config.auto_discovery_key[0] != '\0') {
        KOMARI_LOG_INFO("[AutoDiscovery] Auto-discovery key detected, attempting registration");
        if (autodiscovery_handle(g_config.endpoint,
                                  g_config.auto_discovery_key,
                                  g_config.token,
                                  sizeof(g_config.token)) == 0) {
            KOMARI_LOG_INFO("[AutoDiscovery] Auto-discovery succeeded, token acquired");
        } else {
            KOMARI_LOG_WARN("[AutoDiscovery] Auto-discovery failed");
        }
    }

    /* Initialize the per-process network rate calculation state used by the
     * report thread. The monitoring module no longer holds internal global
     * state; the caller owns the state and passes it explicitly. */
    if (monitoring_net_state_init(&g_net_state) != 0) {
        KOMARI_LOG_ERROR("Failed to initialize network monitoring state");
        return 1;
    }

    if (g_config.token[0] == '\0' || g_config.endpoint[0] == '\0') {
        fprintf(stderr, "Error: token and endpoint are required\n");
        print_usage(argv[0]);
        return 1;
    }

    /* interval is already guaranteed > 0 by config_validate() above; keep
     * a defensive fallback in case a future code path bypasses validation. */
    if (g_config.interval <= 0) {
        g_config.interval = DEFAULT_INTERVAL;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("Komari Agent (C Language Version) v%s\n", KOMARI_AGENT_C_VERSION_STRING);
    printf("Connecting to: %s\n", g_config.endpoint);
    printf("Report interval: %.1f seconds\n", g_config.interval);
    
    char ws_endpoint[512];
    const char *ep = g_config.endpoint;
    if (strncmp(ep, "http://", 7) == 0) {
        snprintf(ws_endpoint, sizeof(ws_endpoint), "ws://%s", ep + 7);
    } else if (strncmp(ep, "https://", 8) == 0) {
        snprintf(ws_endpoint, sizeof(ws_endpoint), "wss://%s", ep + 8);
    } else {
        snprintf(ws_endpoint, sizeof(ws_endpoint), "ws://%s", ep);
    }
    
    /* IDN domain name conversion */
    char ascii_endpoint[512];
    if (idn_convert_url_to_ascii(ws_endpoint, ascii_endpoint, sizeof(ascii_endpoint)) == 0) {
        KOMARI_LOG_DEBUG("IDN converted: %s -> %s", ws_endpoint, ascii_endpoint);
        utils_set_string(ws_endpoint, sizeof(ws_endpoint), ascii_endpoint);
    } else {
        KOMARI_LOG_DEBUG("IDN conversion failed, using original URL");
    }
    
    ws_client_config_t ws_config = {
        .endpoint = ws_endpoint,
        .token = g_config.token,
        .ignore_cert = g_config.ignore_unsafe_cert,
        .prefer_ip_version = g_config.prefer_ip_version,
        .disable_compression = g_config.disable_compression,
        .max_retries = g_config.max_retries,
        .reconnect_interval = g_config.reconnect_interval,
        .report_interval = g_config.interval
    };
    
    g_ws_client = ws_client_create(&ws_config);
    if (!g_ws_client) {
        fprintf(stderr, "Error: Failed to create WebSocket client\n");
        return 1;
    }
    ws_client_set_file_handler(g_ws_client, handle_file_params);
    
    ws_client_set_handler(g_ws_client, handle_ws_message);
    
    if (g_config.month_rotate > 0) {
        g_netstatic = netstatic_create(KOMARI_PATH_NETSTATIC_FILE);
        if (g_netstatic) {
            netstatic_set_month_rotate(g_netstatic, g_config.month_rotate);
            /* Seed the sampler with the filtered interface set so the
             * first run (no persisted history) actually collects data;
             * mirrors the Go root.go SetNewConfig(Nics: InterfaceList()). */
            char ifaces[64][32];
            int n_ifaces = monitoring_list_interfaces(ifaces, 64);
            for (int i = 0; i < n_ifaces; i++) {
                netstatic_add_interface(g_netstatic, ifaces[i]);
            }
            netstatic_start(g_netstatic);
        }
    }

    /* Start background update checker thread (if auto-update not disabled) */
    pthread_t update_tid;
    bool update_tid_valid = false;
    if (!g_config.disable_auto_update) {
        if (pthread_create(&update_tid, NULL, update_do_check_works, NULL) == 0) {
            /* Keep the thread joinable so the shutdown path can wait for it
             * to exit cleanly instead of leaving a detached thread stuck in
             * popen()/pclose() (which would orphan the opkg/apk child process
             * as a zombie when the agent is SIGTERM'd). */
            update_tid_valid = true;
            KOMARI_LOG_INFO("[Update] Background update checker started");
        } else {
            KOMARI_LOG_WARN("[Update] Failed to start update checker thread");
        }
    }

    /* Upload basic info once synchronously before entering the WS loop,
     * mirroring the Go reference (cmd/root.go: UpdateBasicInfo() followed by
     * EstablishWebSocketConnection). The report thread keeps the periodic
     * upload on the info_report_interval ticker. */
    {
        char bi_buf[4096];
        int bi_len = report_generate_basic_info_v2(&g_config, bi_buf, sizeof(bi_buf));
        if (bi_len > 0 &&
            report_upload_basic_info(&g_config, bi_buf, (size_t)bi_len) != 0) {
            KOMARI_LOG_WARN("[Report] Initial basic info upload failed; "
                            "will retry on the report cycle");
        }
    }

    pthread_t report_tid, heartbeat_tid;

    if (pthread_create(&report_tid, NULL, report_thread, NULL) != 0) {
        KOMARI_LOG_ERROR("Failed to create report thread");
        if (g_netstatic) {
            netstatic_stop(g_netstatic);
            netstatic_destroy(g_netstatic);
        }
        ws_client_stop(g_ws_client);
        ws_client_disconnect(g_ws_client);
        ws_client_destroy(g_ws_client);
        logger_cleanup();
        return 1;
    }

    if (pthread_create(&heartbeat_tid, NULL, heartbeat_thread, NULL) != 0) {
        KOMARI_LOG_ERROR("Failed to create heartbeat thread");
        /* Signal report thread to exit and join it before cleanup so it
         * does not keep accessing the ws client we are about to destroy. */
        g_running = 0;
        pthread_join(report_tid, NULL);
        if (g_netstatic) {
            netstatic_stop(g_netstatic);
            netstatic_destroy(g_netstatic);
        }
        ws_client_stop(g_ws_client);
        ws_client_disconnect(g_ws_client);
        ws_client_destroy(g_ws_client);
        logger_cleanup();
        return 1;
    }
    
    while (g_running) {
        sleep(1);
    }

    printf("Stopping service...\n");

    /* Signal the update checker thread to exit its loop promptly
     * (within ~1 second). The thread is joinable, so we wait for it below
     * after the worker threads. If it is stuck in popen()/pclose() the
     * join will block until the opkg/apk child process completes (usually
     * <5 seconds); on timeout we proceed and let the OS reap the child. */
    update_stop();

    /* Signal every active terminal session to wind down. This must happen
     * before joining the report/heartbeat threads so that monitor threads
     * stop touching OpenSSL (via their dedicated ws_client) before main
     * proceeds to OpenSSL cleanup. Monitor threads are joinable and will
     * be joined after the worker threads. */
    sessions_signal_stop();

    /* Set the WebSocket client stop flag so its internal recv thread and
     * the report thread's retry loop can wind down. ws_client_stop only
     * sets a flag under state_mutex; it does NOT destroy the mutex or free
     * memory, so it is safe to call while report/heartbeat threads are
     * still accessing g_ws_client.
     *
     * We intentionally do NOT call ws_client_disconnect/ws_client_destroy
     * here: ws_client_disconnect closes the underlying fd/SSL outside the
     * mutex (racing with any in-progress ws_client_connect in the report
     * thread), and ws_client_destroy calls pthread_mutex_destroy + free,
     * which would turn the report/heartbeat threads' mutex reads into
     * use-after-free. Both are deferred until after the worker threads
     * have been joined below. */
    if (g_ws_client) {
        ws_client_stop(g_ws_client);
    }

    /* Join worker threads BEFORE destroying any shared resources they
     * access. Both report_thread and heartbeat_thread call
     * ws_client_is_connected(g_ws_client) on every loop iteration, which
     * takes the client's state mutex; destroying g_ws_client first would
     * turn those calls into use-after-free. The threads check g_running
     * every second in their sleep loops, so join returns within ~1 second.
     *
     * This mirrors the Go reference implementation's cleanup pattern
     * (.komari-agent-main/server/websocket.go, EstablishWebSocketConnection)
     * where defer conn.Close() and defer heartbeatTicker.Stop() only run
     * after the surrounding goroutine has stopped using them. */
    pthread_join(report_tid, NULL);
    pthread_join(heartbeat_tid, NULL);

    /* Join the update checker thread if it was started. update_stop() above
     * flipped its running flag; the thread's 6-hour sleep is already sliced
     * to 1-second granularity, so it returns within ~1 second. If it is
     * blocked inside popen()/pclose() (opkg/apk invocation), join waits
     * for the child process to finish. */
    if (update_tid_valid) {
        pthread_join(update_tid, NULL);
    }

    /* Join all terminal monitor threads and free their sessions. Each
     * monitor thread tears down its own ws_client/terminal before setting
     * cleanup_done; join ensures that teardown is complete before main
     * touches OpenSSL or exits. This avoids the original M1 bug where
     * detached monitor threads were forcibly killed mid-cleanup. */
    sessions_join_and_cleanup();

    /* All worker threads have exited; it is now safe to free shared
     * resources. netstatic_stop joins its own internal worker thread, so
     * by the time netstatic_destroy returns, all netstatic threads have
     * exited and its mutex can be destroyed safely. */
    if (g_netstatic) {
        netstatic_stop(g_netstatic);
        netstatic_destroy(g_netstatic);
    }

    /* ws_client_disconnect closes the fd/SSL and joins the recv thread;
     * ws_client_destroy frees the SSL_CTX, destroys the send_mutex and
     * state_mutex, and frees the client struct. Both are safe now that
     * no worker thread can access g_ws_client. */
    if (g_ws_client) {
        ws_client_disconnect(g_ws_client);
        ws_client_destroy(g_ws_client);
    }

    monitoring_net_state_cleanup(&g_net_state);

    logger_cleanup();

    printf("Service stopped\n");

    /* OpenSSL 1.1.0+ cleans up automatically; no EVP_cleanup /
     * ERR_remove_state calls are needed. The project requires OpenSSL >= 1.1.0
     * (see cmake/Dependencies.cmake), so the 1.0.2 cleanup path was removed. */

    return 0;
}
