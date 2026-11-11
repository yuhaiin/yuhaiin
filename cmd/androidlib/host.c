//go:build cgo

// Trampolines from Go into the host callback table. cgo forbids C
// definitions in the preamble of a file that uses //export, so they live here.
#include <stdlib.h>
#include "yuhaiin_abi.h"

__attribute__((visibility("hidden"))) int32_t yh_host_protect(const yh_host *h, int32_t fd) {
  return h->protect ? h->protect(h->ctx, fd) : 1;
}

__attribute__((visibility("hidden"))) int64_t yh_host_bind(const yh_host *h, int32_t fd, const char *iface) {
  return h->bind_socket ? h->bind_socket(h->ctx, fd, iface) : 0;
}

__attribute__((visibility("hidden"))) int32_t yh_host_dump_uid(const yh_host *h, int32_t proto, const char *src, int32_t sport,
                         const char *dst, int32_t dport) {
  return h->dump_uid ? h->dump_uid(h->ctx, proto, src, sport, dst, dport) : -1;
}

__attribute__((visibility("hidden"))) int32_t yh_host_establish(const yh_host *h, int64_t generation, const char *config, char **error) {
  if (!h->vpn_establish) return -1;
  return h->vpn_establish(h->ctx, generation, config, error);
}

__attribute__((visibility("hidden"))) int32_t yh_host_call(const yh_host *h, const char *op, const uint8_t *req, size_t req_len,
                     uint8_t **resp, size_t *resp_len) {
  if (!h->call) return -1;
  return h->call(h->ctx, op, req, req_len, resp, resp_len);
}
