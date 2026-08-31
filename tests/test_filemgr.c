/*
 * test_filemgr.c - file manager operation unit tests
 *
 * Test scope (non-streaming ops against a real temp directory):
 *   - resolve_path: ~ expansion, lexical cleaning, traversal collapse
 *   - list/list_roots/stat/create/mkdir/delete/move/copy/chmod/chown/search
 *   - concurrency gate acquire/release
 *   - result envelope shape via filemgr_execute (uuid/request_id/ok/error)
 */

#include "unity.h"
#include "filemgr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

static char tmp_dir[256];
static agent_config_t cfg;

static void rm_rf(const char *path) {
    /* Minimal recursive delete for the fixture. */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf \"%s\"", path);
    if (system(cmd) != 0) {
        /* best effort */
    }
}

void setUp(void) {
    memset(&cfg, 0, sizeof(cfg));
    snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/komari-filemgr-%d", (int)getpid());
    rm_rf(tmp_dir);
    if (mkdir(tmp_dir, 0755) != 0) {
        /* mkdir may fail if leftover; ignore, tests use fresh names. */
    }
    /* Point HOME at the fixture so "~" resolves inside the sandbox. */
    setenv("HOME", tmp_dir, 1);
}

void tearDown(void) {
    rm_rf(tmp_dir);
}

/* ====== resolve_path ====== */

void test_resolve_path_home_expansion(void) {
    char out[1024];
    TEST_ASSERT_EQUAL_INT(0, filemgr_resolve_path("~/dir/file", out, sizeof(out)));
    char expected[512];
    snprintf(expected, sizeof(expected), "%s/dir/file", tmp_dir);
    TEST_ASSERT_EQUAL_STRING(expected, out);
}

void test_resolve_path_lexical_clean(void) {
    char out[1024];
    TEST_ASSERT_EQUAL_INT(0, filemgr_resolve_path("/a/b/../c/./d", out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("/a/c/d", out);

    TEST_ASSERT_EQUAL_INT(0, filemgr_resolve_path("//a///b/", out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("/a/b", out);
}

void test_resolve_path_rejects_control_chars(void) {
    char out[1024];
    TEST_ASSERT_EQUAL_INT(-1, filemgr_resolve_path("/a\r\nX", out, sizeof(out)));
    TEST_ASSERT_EQUAL_INT(-1, filemgr_resolve_path("", out, sizeof(out)));
}

/* ====== mkdir / create / stat / list ====== */

void test_op_mkdir_and_create_and_stat(void) {
    char params_str[512];
    snprintf(params_str, sizeof(params_str),
             "{\"uuid\":\"u1\",\"request_id\":1,\"op\":\"mkdir\","
             "\"args\":{\"path\":\"%s/a/b\",\"mode\":\"0755\"}}", tmp_dir);
    cJSON *params = cJSON_Parse(params_str);
    TEST_ASSERT_NOT_NULL(params);

    cJSON *result = filemgr_execute(&cfg, params);
    TEST_ASSERT_NOT_NULL(result);
    cJSON *ok = cJSON_GetObjectItem(result, "ok");
    TEST_ASSERT_TRUE(cJSON_IsTrue(ok));
    cJSON *res = cJSON_GetObjectItem(result, "result");
    TEST_ASSERT_TRUE(cJSON_IsObject(res));

    /* Target directory exists now. */
    char path[512];
    snprintf(path, sizeof(path), "%s/a/b", tmp_dir);
    struct stat st;
    TEST_ASSERT_EQUAL_INT(0, stat(path, &st));
    TEST_ASSERT_TRUE(S_ISDIR(st.st_mode));

    /* create an empty file inside it */
    cJSON_Delete(result);

    snprintf(params_str, sizeof(params_str),
             "{\"uuid\":\"u1\",\"request_id\":1,\"op\":\"create\","
             "\"args\":{\"path\":\"%s/a/b/file.txt\"}}", tmp_dir);
    params = cJSON_Parse(params_str);
    result = filemgr_execute(&cfg, params);
    TEST_ASSERT_NOT_NULL(result);
    snprintf(path, sizeof(path), "%s/a/b/file.txt", tmp_dir);
    TEST_ASSERT_EQUAL_INT(0, access(path, F_OK));

    /* stat returns a fileInfo */
    cJSON_Delete(result);
    snprintf(params_str, sizeof(params_str),
             "{\"uuid\":\"u1\",\"request_id\":1,\"op\":\"stat\","
             "\"args\":{\"path\":\"%s/a/b/file.txt\"}}", tmp_dir);
    params = cJSON_Parse(params_str);
    result = filemgr_execute(&cfg, params);
    cJSON *res2 = cJSON_GetObjectItem(result, "result");
    TEST_ASSERT_TRUE(cJSON_IsObject(res2));
    TEST_ASSERT_EQUAL_STRING("file.txt",
                             cJSON_GetObjectItem(res2, "name")->valuestring);
    TEST_ASSERT_FALSE(cJSON_IsTrue(cJSON_GetObjectItem(res2, "is_dir")));

    cJSON_Delete(result);
    cJSON_Delete(params);
}

void test_op_list_orders_dirs_first(void) {
    char p[512];
    snprintf(p, sizeof(p), "%s/zdir", tmp_dir);
    TEST_ASSERT_EQUAL_INT(0, mkdir(p, 0755));
    snprintf(p, sizeof(p), "%s/zdir/inner.txt", tmp_dir);
    FILE *f = fopen(p, "w");
    TEST_ASSERT_NOT_NULL(f);
    fputs("x", f);
    fclose(f);
    snprintf(p, sizeof(p), "%s/afile.txt", tmp_dir);
    f = fopen(p, "w");
    TEST_ASSERT_NOT_NULL(f);
    fputs("x", f);
    fclose(f);

    char params_str[512];
    snprintf(params_str, sizeof(params_str),
             "{\"uuid\":\"u\",\"request_id\":1,\"op\":\"list\","
             "\"args\":{\"path\":\"%s\"}}", tmp_dir);
    cJSON *params = cJSON_Parse(params_str);
    cJSON *result = filemgr_execute(&cfg, params);
    TEST_ASSERT_NOT_NULL(result);
    cJSON *res = cJSON_GetObjectItem(result, "result");
    TEST_ASSERT_TRUE(cJSON_IsArray(res));

    /* First entry must be the directory. */
    cJSON *first = cJSON_GetArrayItem(res, 0);
    TEST_ASSERT_EQUAL_STRING("zdir", cJSON_GetObjectItem(first, "name")->valuestring);
    TEST_ASSERT_TRUE(cJSON_IsTrue(cJSON_GetObjectItem(first, "is_dir")));

    cJSON_Delete(result);
    cJSON_Delete(params);
}

/* ====== move / copy / delete ====== */

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    TEST_ASSERT_NOT_NULL(f);
    fputs(content, f);
    fclose(f);
}

void test_op_move_copy_delete(void) {
    char a[512], b[512], c[512];
    snprintf(a, sizeof(a), "%s/src.txt", tmp_dir);
    snprintf(b, sizeof(b), "%s/copy.txt", tmp_dir);
    snprintf(c, sizeof(c), "%s/moved.txt", tmp_dir);
    write_file(a, "payload");

    char params_str[768];

    /* copy */
    snprintf(params_str, sizeof(params_str),
             "{\"uuid\":\"u\",\"request_id\":1,\"op\":\"copy\",\"args\":{"
             "\"source\":\"%s\",\"destination\":\"%s\"}}", a, b);
    cJSON *params = cJSON_Parse(params_str);
    cJSON *result = filemgr_execute(&cfg, params);
    TEST_ASSERT_TRUE(cJSON_IsTrue(cJSON_GetObjectItem(result, "ok")));
    cJSON_Delete(result);
    cJSON_Delete(params);
    TEST_ASSERT_EQUAL_INT(0, access(b, F_OK));

    /* move */
    snprintf(params_str, sizeof(params_str),
             "{\"uuid\":\"u\",\"request_id\":1,\"op\":\"move\",\"args\":{"
             "\"source\":\"%s\",\"destination\":\"%s\"}}", b, c);
    params = cJSON_Parse(params_str);
    result = filemgr_execute(&cfg, params);
    TEST_ASSERT_TRUE(cJSON_IsTrue(cJSON_GetObjectItem(result, "ok")));
    cJSON_Delete(result);
    cJSON_Delete(params);
    TEST_ASSERT_EQUAL_INT(-1, access(b, F_OK));
    TEST_ASSERT_EQUAL_INT(0, access(c, F_OK));

    /* delete */
    snprintf(params_str, sizeof(params_str),
             "{\"uuid\":\"u\",\"request_id\":1,\"op\":\"delete\","
             "\"args\":{\"path\":\"%s\"}}", c);
    params = cJSON_Parse(params_str);
    result = filemgr_execute(&cfg, params);
    TEST_ASSERT_TRUE(cJSON_IsTrue(cJSON_GetObjectItem(result, "ok")));
    cJSON_Delete(result);
    cJSON_Delete(params);
    TEST_ASSERT_EQUAL_INT(-1, access(c, F_OK));

    /* delete rejects root */
    params = cJSON_Parse("{\"uuid\":\"u\",\"request_id\":1,\"op\":\"delete\","
                         "\"args\":{\"path\":\"/\"}}");
    result = filemgr_execute(&cfg, params);
    TEST_ASSERT_FALSE(cJSON_IsTrue(cJSON_GetObjectItem(result, "ok")));
    TEST_ASSERT_NOT_NULL(strstr(cJSON_GetObjectItem(result, "error")->valuestring,
                                "root"));
    cJSON_Delete(result);
    cJSON_Delete(params);
}

void test_op_chmod(void) {
    char p[512];
    snprintf(p, sizeof(p), "%s/mode.txt", tmp_dir);
    write_file(p, "x");

    char params_str[768];
    snprintf(params_str, sizeof(params_str),
             "{\"uuid\":\"u\",\"request_id\":1,\"op\":\"chmod\",\"args\":{"
             "\"path\":\"%s\",\"mode\":\"0o640\"}}", p);
    cJSON *params = cJSON_Parse(params_str);
    cJSON *result = filemgr_execute(&cfg, params);
    TEST_ASSERT_TRUE(cJSON_IsTrue(cJSON_GetObjectItem(result, "ok")));
    cJSON *res = cJSON_GetObjectItem(result, "result");
    TEST_ASSERT_EQUAL_STRING("0640",
                             cJSON_GetObjectItem(res, "mode")->valuestring);

    struct stat st;
    TEST_ASSERT_EQUAL_INT(0, stat(p, &st));
    TEST_ASSERT_EQUAL_INT(0640, st.st_mode & 07777);

    cJSON_Delete(result);
    cJSON_Delete(params);
}

void test_op_search_name(void) {
    char p[512];
    snprintf(p, sizeof(p), "%s/findme.txt", tmp_dir);
    write_file(p, "needle in content");
    snprintf(p, sizeof(p), "%s/other.bin", tmp_dir);
    write_file(p, "nothing");

    char params_str[768];
    snprintf(params_str, sizeof(params_str),
             "{\"uuid\":\"u\",\"request_id\":1,\"op\":\"search\",\"args\":{"
             "\"path\":\"%s\",\"query\":\"findme\",\"content\":false}}", tmp_dir);
    cJSON *params = cJSON_Parse(params_str);
    cJSON *result = filemgr_execute(&cfg, params);
    TEST_ASSERT_NOT_NULL(result);
    cJSON *res = cJSON_GetObjectItem(result, "result");
    cJSON *matches = cJSON_GetObjectItem(res, "matches");
    TEST_ASSERT_TRUE(cJSON_IsArray(matches));
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(matches));

    cJSON_Delete(result);
    cJSON_Delete(params);
}

/* ====== list_roots ====== */

void test_op_list_roots(void) {
    cJSON *params = cJSON_Parse("{\"uuid\":\"u\",\"request_id\":1,\"op\":\"list_roots\",\"args\":{}}");
    cJSON *result = filemgr_execute(&cfg, params);
    cJSON *res = cJSON_GetObjectItem(result, "result");
    TEST_ASSERT_TRUE(cJSON_IsArray(res));
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(res));
    cJSON *root = cJSON_GetArrayItem(res, 0);
    TEST_ASSERT_EQUAL_STRING("/", cJSON_GetObjectItem(root, "path")->valuestring);
    cJSON_Delete(result);
    cJSON_Delete(params);
}

/* ====== unsupported op + gate ====== */

void test_unsupported_op_reports_error(void) {
    cJSON *params = cJSON_Parse("{\"uuid\":\"u\",\"request_id\":1,\"op\":\"teleport\",\"args\":{}}");
    cJSON *result = filemgr_execute(&cfg, params);
    TEST_ASSERT_FALSE(cJSON_IsTrue(cJSON_GetObjectItem(result, "ok")));
    TEST_ASSERT_NOT_NULL(strstr(cJSON_GetObjectItem(result, "error")->valuestring,
                                "unsupported"));
    cJSON_Delete(result);
    cJSON_Delete(params);
}

void test_gate_reflects_disable_web_ssh(void) {
    cfg.disable_web_ssh = false;
    TEST_ASSERT_TRUE(filemgr_allowed(&cfg));
    cfg.disable_web_ssh = true;
    TEST_ASSERT_FALSE(filemgr_allowed(&cfg));
}

void test_concurrency_gate(void) {
    /* Drain and refill the gate; try_acquire must succeed when free. */
    filemgr_release(); /* compensate in case of prior leakage */
    TEST_ASSERT_EQUAL_INT(0, filemgr_try_acquire());
    filemgr_release();
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_resolve_path_home_expansion);
    RUN_TEST(test_resolve_path_lexical_clean);
    RUN_TEST(test_resolve_path_rejects_control_chars);
    RUN_TEST(test_op_mkdir_and_create_and_stat);
    RUN_TEST(test_op_list_orders_dirs_first);
    RUN_TEST(test_op_move_copy_delete);
    RUN_TEST(test_op_chmod);
    RUN_TEST(test_op_search_name);
    RUN_TEST(test_op_list_roots);
    RUN_TEST(test_unsupported_op_reports_error);
    RUN_TEST(test_gate_reflects_disable_web_ssh);
    RUN_TEST(test_concurrency_gate);

    return UNITY_END();
}
