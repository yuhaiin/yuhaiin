# Android C ABI

The Android core is `cmd/androidlib` built with `-buildmode=c-shared`
(`make yuhaiin_android_so`), producing `libyuhaiin.so` per ABI. It replaces the
gomobile AAR. The Go core in `cmd/android` is unchanged; `cmd/androidlib` only
connects it to the platform.

There is a single native library. The JNI bridge (`cmd/androidlib/jni_android.c`)
is compiled by cgo into `libyuhaiin.so` itself, so the app calls
`System.loadLibrary("yuhaiin")` and `JNI_OnLoad`/`Java_*` entry points call
`yh_call` directly (no second `.so`, no CMake in the app). The Go runtime starts
when the library is loaded, before `JNI_OnLoad`.

The contract is [`cmd/androidlib/yuhaiin_abi.h`](../cmd/androidlib/yuhaiin_abi.h)
(`YH_ABI_VERSION 1`). It has three functions and one callback table:

```c
uint32_t yh_abi_version(void);
int32_t  yh_call(const char *op, const uint8_t *req, size_t req_len,
                 uint8_t **resp, size_t *resp_len);
void     yh_free(void *ptr);
int32_t  yh_set_host(const yh_host *host);
```

## Rules

* **Ownership.** Every buffer is `malloc`ed by its producer. A `yh_call`
  response is released with `yh_free`; a host callback response or error string
  is released by the core with `free`. Inputs are borrowed for the call. No Go
  pointer or object is visible to the host, and the host keeps no handle to Go.
* **Status.** `0` is success. Negative: `-1` failed (response is a UTF-8
  message), `-2` unknown operation, `-3` bad request, `-4` Go panic recovered,
  `-5` no host installed. A Go panic never unwinds into C.
* **Payloads** are JSON, except the operations marked *raw*.
* **Threads.** `yh_call` is thread safe. Host callbacks run on Go threads; the
  JNI bridge attaches them to the JVM itself.
* **Stopped core.** `protect`, `bind_socket`, `dump_uid`, `vpn_establish` and
  `vpn.status_changed` return their neutral answer without reaching the host
  while the core is stopped, so a late callback of an old core can not act on
  the next one. `vpn.release` is always forwarded so descriptors are never
  leaked.

## Operations (`yh_call`)

| Operation | Request → response |
|---|---|
| `core.init` | `{savePath, configLockPath, managementTLSDir}`; once, before anything else |
| `core.start` / `core.stop` | `{}` |
| `core.session` | `{}` → `{running, port, token}` |
| `core.native_status`, `core.health`, `vpn.status` | `{}` → raw JSON |
| `core.monitoring` | `{online, metered, foreground}` |
| `core.vpn_enabled` / `core.set_vpn_enabled` | `{}` → `{enabled}` / `{enabled}` |
| `vpn.revoked` | `{generation}` → `{applied}` |
| `vpn.reconfigure` | `{}` |
| `network.report` | `{selected, networks:[{handle, interfaceIndex, interfaceName, addresses, available, validated, vpn}]}` |
| `net.is_ipv6`, `net.parse_cidr` | `{}` → `{ipv6}`; `{cidrs}` → `{prefixes:[{ip,mask}]}` |
| `store.get` / `store.put` | `{keys:[{key,type}]}` → `{values}`; `{entries:[{key,type,value}]}` (types `string int bool long float bytes`) |
| `config.export` / `config.validate` / `config.import` | *raw* backup bytes |
| `proxy.get` / `proxy.download` | `{url}` → *raw*; `{url, destination}` |

Everything else (settings, nodes, rules, connections, …) stays on the existing
HTTP API. A new core feature should normally need no ABI change.

## Host callbacks (`yh_host`)

Dedicated integer-only entries for hot paths: `protect(fd)`,
`bind_socket(fd, interface)`, `dump_uid(...)`, `vpn_establish(generation,
config_json, &error)`. The TUN descriptor stays owned by the host; the core
duplicates it. Packets never cross the boundary.

`call(op, ...)` serves the rest: `interfaces.list`, `uid.name`,
`vpn.release`, `vpn.authorization`, `vpn.status_changed`, `core.closed`,
`apps.list`, `apps.icon`, and `platform.{restore_config, restart_core,
privacy_state, withdraw_consent, update_state, update_action, app_info}`.
Handlers must return quickly and must not call `core.stop`/`core.start`
synchronously.

## Compatibility

Adding an operation, a request/response field, or an `yh_host` field appended
at the end (the core checks `yh_host.size`) is compatible. Renaming or changing
the meaning of anything above, or changing a function signature or ownership
rule, requires `YH_ABI_VERSION` to be incremented; the host refuses to load a
core with a different version.

`make test_android_abi` builds the library for the host and runs a C harness
(`cmd/androidlib/testdata/abi_harness.c`) against it.
