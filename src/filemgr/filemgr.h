/*
 * File manager operations (agent.file / agent.file.result), mirroring the
 * Go reference server/files.go.
 *
 * Supported ops: list, list_roots, stat, create, mkdir, delete, move, copy,
 * chmod, chown, search, download_stream, upload_stream, upload_commit,
 * upload_cancel. Paths are resolved relative to the agent user's home
 * (leading ~) and cleaned before use. Results are reported back to the
 * panel as agent.file.result JSON-RPC requests over the v2 RPC endpoint.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#ifndef KOMARI_AGENT_C_FILEMGR_H
#define KOMARI_AGENT_C_FILEMGR_H

#include <stdbool.h>
#include <stddef.h>

#include "cJSON.h"
#include "config.h"
#include "common.h"

/* Concurrent file-operation cap (Go maxFileStreamOperations). */
#define FILEMGR_MAX_CONCURRENT 8

/* Search limits (Go searchResultLimit / content size cap). */
#define FILEMGR_SEARCH_LIMIT 500
#define FILEMGR_SEARCH_CONTENT_MAX (10 * 1024 * 1024)

/* Transfer chunk bounds (Go defaultTransferChunkSize / maxTransferChunkSize). */
#define FILEMGR_CHUNK_DEFAULT (25u * 1024u * 1024u)
#define FILEMGR_CHUNK_MAX (128u * 1024u * 1024u)

/**
 * Gate: true when file operations are allowed (disable_web_ssh off).
 * Mirrors the Go executeFileOperation guard ("web control is disabled").
 */
bool filemgr_allowed(const agent_config_t *config);

/**
 * Execute a file operation described by an agent.file params object:
 * { uuid, request_id, op, args }.
 *
 * The operation runs synchronously; callers that need concurrency spawn
 * this on their own thread (bounded by filemgr_try_acquire /
 * filemgr_release). The result object (agent.file.result params shape:
 * { uuid, request_id, ok, result, error }) is returned as a heap cJSON
 * tree the caller must free with cJSON_Delete.
 *
 * @param config Agent configuration (used by the streaming ops)
 * @param params Parsed agent.file params object (borrowed; not freed)
 * @return Heap-allocated agent.file.result params object, or NULL when
 *         the request is malformed (in which case the caller should log
 *         and skip the result upload).
 */
cJSON *filemgr_execute(const agent_config_t *config, const cJSON *params);

/**
 * Upload a file-result object to the panel (agent.file.result request,
 * POST /api/clients/v2/rpc). No compression; up to 4 attempts with
 * 500ms*attempt backoff; 4xx responses abort retrying. Mirrors
 * files.go sendFileResult.
 *
 * @param config Agent configuration
 * @param result_params The agent.file.result params object (ownership is
 *                      taken; freed before return)
 * @return 0 when the panel accepted the result, -1 otherwise
 */
int filemgr_upload_result(const agent_config_t *config, cJSON *result_params);

/* Concurrency gate (used by tests and the dispatch layer). */
int filemgr_try_acquire(void);
void filemgr_release(void);

/* Shared helpers (implemented in filemgr.c, used by filemgr_stream.c). */

/* Resolve a request path (~ expansion + lexical clean). */
int filemgr_resolve_path(const char *raw, char *out, size_t out_len);

/* Build "<endpoint>/api/clients/v2/rpc?token=<encoded>". */
int filemgr_build_rpc_url(const agent_config_t *config, char *url,
                          size_t url_len);

/* Recursive directory removal (RemoveAll semantics). */
int filemgr_remove_tree(const char *path, int depth);

#endif /* KOMARI_AGENT_C_FILEMGR_H */
