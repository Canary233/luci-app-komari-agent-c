/*
 * test_fallback.c - POST fallback channel unit tests
 *
 * Test scope:
 *   - fallback_build_pull_request: capabilities list and ACK array
 *   - fallback_extract_events: result.events extraction and error shapes
 *
 * The agent.report envelope is produced by report_generate_v2_with_acks_ex
 * (covered by test_report.c); no duplicate builder exists in fallback.c.
 */

#include "unity.h"
#include "fallback.h"

#include <stdlib.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ====== fallback_build_pull_request ====== */

void test_fallback_pull_request_shape(void) {
    char *out = NULL;
    TEST_ASSERT_EQUAL_INT(0, fallback_build_pull_request(99, NULL, 0, &out));
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NOT_NULL(strstr(out,
        "{\"jsonrpc\":\"2.0\",\"id\":\"pull-99\",\"method\":\"agent.pull\""));
    /* Capabilities list matches the Go reference. */
    TEST_ASSERT_NOT_NULL(strstr(out,
        "\"capabilities\":[\"exec\",\"ping\",\"message\",\"event\",\"terminal\",\"file\"]"));
    TEST_ASSERT_NOT_NULL(strstr(out, "\"ack_event_ids\":[]"));
    free(out);
}

void test_fallback_pull_request_with_acks(void) {
    int acks[] = {3};
    char *out = NULL;
    TEST_ASSERT_EQUAL_INT(0, fallback_build_pull_request(1, acks, 1, &out));
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NOT_NULL(strstr(out, "\"ack_event_ids\":[3]"));
    free(out);
}

/* ====== fallback_extract_events ====== */

void test_fallback_extract_events_ok(void) {
    const char *body =
        "{\"jsonrpc\":\"2.0\",\"id\":\"pull-1\",\"result\":{"
        "\"status\":\"ok\","
        "\"events\":["
        "{\"id\":\"5\",\"method\":\"agent.exec\",\"params\":{\"task_id\":\"t\",\"command\":\"ls\"}},"
        "{\"id\":\"6\",\"method\":\"agent.message\",\"params\":{}}"
        "]}}";
    cJSON *root = cJSON_Parse(body);
    TEST_ASSERT_NOT_NULL(root);

    const cJSON *events = NULL;
    int n = fallback_extract_events(root, &events);
    TEST_ASSERT_EQUAL_INT(2, n);
    TEST_ASSERT_NOT_NULL(events);

    const cJSON *first = cJSON_GetArrayItem(events, 0);
    cJSON *method = cJSON_GetObjectItem(first, "method");
    TEST_ASSERT_EQUAL_STRING("agent.exec", method->valuestring);

    cJSON_Delete(root);
}

void test_fallback_extract_events_empty_or_error(void) {
    /* No result object (JSON-RPC error). */
    cJSON *err = cJSON_Parse("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1,\"message\":\"x\"}}");
    const cJSON *events = NULL;
    TEST_ASSERT_EQUAL_INT(-1, fallback_extract_events(err, &events));
    cJSON_Delete(err);

    /* Result without events array => 0 events. */
    cJSON *empty = cJSON_Parse("{\"result\":{\"status\":\"ok\"}}");
    TEST_ASSERT_EQUAL_INT(0, fallback_extract_events(empty, &events));
    cJSON_Delete(empty);

    /* Invalid arguments. */
    TEST_ASSERT_EQUAL_INT(-1, fallback_extract_events(NULL, &events));
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_fallback_pull_request_shape);
    RUN_TEST(test_fallback_pull_request_with_acks);
    RUN_TEST(test_fallback_extract_events_ok);
    RUN_TEST(test_fallback_extract_events_empty_or_error);

    return UNITY_END();
}
