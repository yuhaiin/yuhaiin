/* C-level conformance test for yuhaiin_abi.h, run by abi_test.sh against a
 * c-shared build of this package. It plays the role of the JNI bridge. */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "yuhaiin_abi.h"

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); exit(1);} } while (0)

static int g_closed, g_protect, g_status;

static int32_t h_protect(void *ctx, int32_t fd) { (void)ctx; (void)fd; g_protect++; return 1; }
static int64_t h_bind(void *ctx, int32_t fd, const char *i) { (void)ctx; (void)fd; (void)i; return 0; }
static int32_t h_uid(void *ctx, int32_t p, const char *s, int32_t sp, const char *d, int32_t dp) {
  (void)ctx; (void)p; (void)s; (void)sp; (void)d; (void)dp; return 1000;
}
static int32_t h_establish(void *ctx, int64_t g, const char *cfg, char **err) {
  (void)ctx; (void)g; (void)cfg; *err = strdup("provider_unavailable: test"); return -1;
}
static int32_t h_call(void *ctx, const char *op, const uint8_t *req, size_t n, uint8_t **resp, size_t *rn) {
  (void)ctx; (void)req; (void)n;
  if (!strcmp(op, "core.closed")) { g_closed++; return 0; }
  if (!strcmp(op, "vpn.status_changed")) { g_status++; return 0; }
  if (!strcmp(op, "vpn.authorization")) {
    const char *s = "{\"prepared\":true,\"consent\":true,\"alwaysOn\":false,\"lockdown\":false}";
    *resp = (uint8_t *)strdup(s); *rn = strlen(s); return 0;
  }
  const char *m = "unsupported in harness";
  *resp = (uint8_t *)strdup(m); *rn = strlen(m); return -1;
}

static int32_t call(const char *op, const char *req, char **out) {
  uint8_t *resp = NULL; size_t n = 0;
  int32_t st = yh_call(op, (const uint8_t *)req, req ? strlen(req) : 0, &resp, &n);
  if (out) { *out = resp ? strndup((char *)resp, n) : strdup(""); }
  if (resp) yh_free(resp);
  return st;
}

static void *worker(void *arg) {
  (void)arg;
  for (int i = 0; i < 200; i++) {
    char *o;
    CHECK(call("store.put", "{\"entries\":[{\"key\":\"k\",\"type\":\"int\",\"value\":5}]}", &o) == 0); free(o);
    CHECK(call("store.get", "{\"keys\":[{\"key\":\"k\",\"type\":\"int\"}]}", &o) == 0); free(o);
    CHECK(call("core.session", NULL, &o) == 0); free(o);
  }
  return NULL;
}

int main(int argc, char **argv) {
  CHECK(argc == 2);
  CHECK(yh_abi_version() == YH_ABI_VERSION);
  char *o;

  CHECK(call("does.not.exist", NULL, &o) == YH_ERR_UNKNOWN_OP); free(o);
  CHECK(call("store.get", "{bad", &o) == YH_ERR_BAD_REQUEST); free(o);
  CHECK(call("store.get", NULL, NULL) == 0); /* empty request, NULL out params tolerated */
  CHECK(yh_call(NULL, NULL, 0, NULL, NULL) == YH_ERR_BAD_REQUEST);

  /* An old host struct is rejected instead of being read out of bounds. */
  yh_host small = {.size = 8};
  CHECK(yh_set_host(&small) == YH_ERR_BAD_REQUEST);

  char req[1024];
  snprintf(req, sizeof req, "{\"savePath\":\"%s\",\"configLockPath\":\"%s/lock\",\"managementTLSDir\":\"%s/tls\"}", argv[1], argv[1], argv[1]);
  CHECK(call("core.init", req, &o) == 0); free(o);

  CHECK(call("store.put", "{\"entries\":[{\"key\":\"s\",\"type\":\"string\",\"value\":\"hello\"},{\"key\":\"b\",\"type\":\"bool\",\"value\":true},{\"key\":\"l\",\"type\":\"long\",\"value\":9007199254740993},{\"key\":\"y\",\"type\":\"bytes\",\"value\":\"AQID\"}]}", &o) == 0); free(o);
  CHECK(call("store.get", "{\"keys\":[{\"key\":\"s\",\"type\":\"string\"},{\"key\":\"b\",\"type\":\"bool\"},{\"key\":\"l\",\"type\":\"long\"},{\"key\":\"y\",\"type\":\"bytes\"}]}", &o) == 0);
  CHECK(strstr(o, "\"hello\"") && strstr(o, "true") && strstr(o, "9007199254740993") && strstr(o, "AQID")); free(o);

  yh_host host = {.size = sizeof host, .ctx = NULL, .protect = h_protect, .bind_socket = h_bind,
                  .dump_uid = h_uid, .vpn_establish = h_establish, .call = h_call};
  CHECK(yh_set_host(&host) == 0);

  for (int round = 0; round < 3; round++) {
    CHECK(call("core.start", NULL, &o) == 0); free(o);
    CHECK(call("core.session", NULL, &o) == 0);
    CHECK(strstr(o, "\"running\":true") && !strstr(o, "\"port\":0,")); free(o);
    CHECK(call("core.start", NULL, &o) != 0); /* already running */ free(o);
    CHECK(call("core.native_status", NULL, &o) == 0); free(o);
    CHECK(call("vpn.status", NULL, &o) == 0); free(o);
    pthread_t t[4];
    for (int i = 0; i < 4; i++) pthread_create(&t[i], NULL, worker, NULL);
    for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);
    CHECK(call("core.stop", NULL, &o) == 0); free(o);
    CHECK(call("core.session", NULL, &o) == 0);
    CHECK(strstr(o, "\"running\":false")); free(o);
  }
  CHECK(g_closed == 3); /* one core.closed per stop */

  CHECK(call("config.export", NULL, &o) == 0); CHECK(strlen(o) > 0); free(o);
  CHECK(yh_set_host(NULL) == 0);
  yh_free(NULL);
  puts("ABI harness OK");
  return 0;
}
