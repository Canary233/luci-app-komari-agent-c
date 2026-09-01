/*
 * POST fallback channel (agent.pull / agent.report over HTTP).
 *
 * When the WebSocket connection cannot be established after max_retries,
 * the agent keeps reporting via HTTP POST to /api/clients/v2/rpc and polls
 * for pending server events with agent.pull, mirroring the Go reference
 * (server/websocket.go runPostFallback / runV2PullLoop / postV2Request).
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#ifndef KOMARI_AGENT_C_FALLBACK_H
#define KOMARI_AGENT_C_FALLBACK_H

#include <stdbool.h>
#include <stddef.h>

#include "config.h"
#include "cJSON.h"

/* Capabilities declared in the agent.pull request, mirroring the Go
 * reference (websocket.go runV2PullLoop). */
#define FALLBACK_CAPABILITIES \
    "exec", "ping", "message", "event", "terminal", "file"

/**
 * POST a JSON-RPC request body to <endpoint>/api/clients/v2/rpc?token=...
 * and return the parsed response body as a cJSON tree.
 *
 * @param config            Agent configuration (endpoint, token, ignore_cert)
 * @param request_body      Pre-built JSON-RPC request body (NUL-terminated)
 * @param gzip              Whether to gzip the body (Content-Encoding: gzip)
 * @param timeout_sec       HTTP timeout in seconds (0 => client default 30)
 * @param response_out      Outputs a parsed cJSON tree of the response body.
 *                          Set to NULL on failure. The caller frees it with
 *                          cJSON_Delete.
 * @return 0 when the server answered 2xx (check response_out for JSON-RPC
 *         error objects), -1 on transport failure or a non-2xx status.
 */
int fallback_post_rpc(const agent_config_t *config, const char *request_body,
                      bool gzip, int timeout_sec, cJSON **response_out);

/**
 * Build an agent.pull JSON-RPC request, mirroring the Go reference:
 * params = { capabilities: [...], ack_event_ids: [...] }.
 *
 * Report envelopes are produced directly by
 * report_generate_v2_with_acks_ex (see report.h); no builder exists here
 * to avoid two implementations of the same wire format.
 *
 * @param pull_id    Request id string ("pull-<unix>" in the Go reference)
 * @param ack_ids    Pending ACK IDs; may be NULL when ack_count is 0
 * @param ack_count  Number of ACK IDs
 * @param out        Outputs a heap-allocated JSON string; caller frees
 * @return 0 on success, -1 on failure
 */
int fallback_build_pull_request(long pull_id, const int *ack_ids,
                                int ack_count, char **out);

/**
 * Extract the events array from an agent.pull / agent.report response body.
 *
 * @param response Parsed JSON-RPC response root (result.status/events shape)
 * @param events   Outputs the "result.events" cJSON array node. The node is
 *                 owned by the response tree (do not free separately).
 * @return Number of events (>= 0); -1 when the response carries no result
 *         object (JSON-RPC error or malformed body).
 */
int fallback_extract_events(const cJSON *response, const cJSON **events);

#endif /* KOMARI_AGENT_C_FALLBACK_H */
