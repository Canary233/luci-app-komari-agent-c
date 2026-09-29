/*
 * File manager streaming ops over the panel transfer endpoint, mirroring
 * server/file_stream.go.
 *
 * Both directions POST to /api/clients/transfer/<transfer_id> with
 * X-Komari-Transfer-* headers:
 *   - download_stream: the agent uploads a file chunk as the request body.
 *   - upload_stream:   the agent sends an empty body and reads the chunk
 *                      from the response body, writing it into a part file.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#ifndef KOMARI_AGENT_C_FILEMGR_STREAM_H
#define KOMARI_AGENT_C_FILEMGR_STREAM_H

#include <stdbool.h>
#include <stddef.h>

#include "cJSON.h"
#include "config.h"

/**
 * Execute one of the four streaming ops.
 *
 * @param op       "download_stream" | "upload_stream" | "upload_commit" |
 *                 "upload_cancel"
 * @param args     op args object (borrowed)
 * @param config   Agent configuration
 * @param err      Error output buffer (on failure)
 * @param err_len  Size of err
 * @return Result cJSON object (ownership passes to the caller), or NULL on
 *         failure with err filled.
 */
cJSON *filemgr_stream_op(const char *op, const cJSON *args,
                         const agent_config_t *config, char *err,
                         size_t err_len);

#endif /* KOMARI_AGENT_C_FILEMGR_STREAM_H */
