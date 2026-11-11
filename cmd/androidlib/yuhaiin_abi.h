/*
 * yuhaiin Android C ABI (version 1).
 *
 * libyuhaiin.so is the Go core built with -buildmode=c-shared. This header is
 * the whole contract between the core and the JNI bridge in yuhaiin-android.
 *
 * Memory ownership
 *   - Every buffer that crosses this boundary is allocated with the C library
 *     malloc() by its producer and has exactly one owner at a time.
 *   - Buffers returned by the core (yh_call response) are released with
 *     yh_free().
 *   - Buffers returned by the host (yh_host.call response, error strings) are
 *     released by the core with free().
 *   - Input pointers are borrowed for the duration of the call only.
 *   - No Go pointer, Go handle or Go object is ever visible to the host.
 *
 * Status codes (yh_call and yh_host.call): 0 is success. A negative status
 * means the response, if any, is a UTF-8 error message.
 *
 * Threading
 *   - yh_call may be invoked from any thread and concurrently.
 *   - Host callbacks run on Go-owned threads. The host attaches them to the
 *     JVM itself and must not assume the thread identity between callbacks.
 *   - A host callback must not call back into yh_call for the same operation
 *     that is waiting for it (for example core.stop from vpn_establish).
 *
 * Payloads are UTF-8 JSON unless an operation is documented as raw bytes.
 */
#ifndef YUHAIIN_ABI_H
#define YUHAIIN_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Incremented only for an incompatible change to this header. New operations
 * and new yh_host fields (appended, guarded by yh_host.size) do not change it. */
#define YH_ABI_VERSION 1u

#define YH_OK 0
#define YH_ERR (-1)            /* the operation failed; response is the message */
#define YH_ERR_UNKNOWN_OP (-2) /* no such operation */
#define YH_ERR_BAD_REQUEST (-3)
#define YH_ERR_PANIC (-4)      /* a Go panic was recovered */
#define YH_ERR_NO_HOST (-5)    /* the host callback table is not installed */

#ifndef YH_NO_EXPORT_DECLS
uint32_t yh_abi_version(void);

/* Low-frequency control operations. operation is a NUL-terminated name such as
 * "core.start". On return the response pointer and length describe a malloc()ed
 * buffer owned by the caller (release with yh_free), or NULL/0 when empty. */
int32_t yh_call(const char *operation, const uint8_t *request, size_t request_len,
                uint8_t **response, size_t *response_len);

void yh_free(void *ptr);
#endif /* YH_NO_EXPORT_DECLS */

/* Platform callbacks. Hot paths have dedicated entries with integer-only
 * signatures; everything else goes through call(). */
typedef struct yh_host {
  uint32_t size; /* sizeof(yh_host) as compiled by the host */
  void *ctx;     /* passed back as the first argument of every callback */

  /* VpnService.protect(fd). Returns non-zero on success. */
  int32_t (*protect)(void *ctx, int32_t fd);
  /* Binds an outbound socket to a platform Network. Returns the Network
   * handle, 0 when unknown, or -1 on failure. interface may be "". */
  int64_t (*bind_socket)(void *ctx, int32_t fd, const char *interface_name);
  /* Owner uid of a connection, or a negative value on failure. */
  int32_t (*dump_uid)(void *ctx, int32_t protocol, const char *src_ip, int32_t src_port,
                      const char *dst_ip, int32_t dst_port);
  /* Builds a VPN interface for generation and returns its descriptor (the host
   * keeps ownership of the original; the core duplicates it). On failure
   * returns a negative value and sets *error to a malloc()ed message. */
  int32_t (*vpn_establish)(void *ctx, int64_t generation, const char *config_json, char **error);
  /* Everything else (see the operation list in the Go sources). */
  int32_t (*call)(void *ctx, const char *operation, const uint8_t *request, size_t request_len,
                  uint8_t **response, size_t *response_len);
} yh_host;

/* Installs a copy of *host (NULL uninstalls). The host must keep ctx valid
 * until it is uninstalled. */
#ifndef YH_NO_EXPORT_DECLS
int32_t yh_set_host(const yh_host *host);
#endif

#ifdef __cplusplus
}
#endif
#endif
