# ZeroTier outbound

ZeroTier joins a controller-managed **virtual Ethernet (L2)** network through
[zerotier-go](https://github.com/yuhaiin/zerotier-go), which embeds the official
ZeroTierOne Core behind a purego ABI. yuhaiin uses its **lightweight TCP/IP
stack** for application TCP/UDP sockets. This outbound never creates a system
TUN, TAP, or network interface and never installs host routes.

## Configuration

Add a `zerotier` protocol as the **first (root)** step in a node chain,
or select the ZeroTier node template in the web UI. Higher-level wrappers may follow, but a preceding outbound is not supported:

```json
{
  "type": "zerotier",
  "zerotier": {
    "network_id": "8056c2e21c000001",
    "identity": "office",
    "listen": ":0",
    "low_bandwidth": false,
    "moons": [
      { "id": "0123456789abcdef", "seed": "0000000123" }
    ]
  }
}
```

- `network_id` (required): **exactly 16 hexadecimal digits**, as shown by your
  controller.
- `identity` (optional): ASCII letters, numbers, `_`, or `-`, at most 64
  characters. The default is the network ID. It picks the identity directory,
  not the ZeroTier address. Use distinct values for simultaneously active
  nodes. Reusing the same identity across processes is unsafe.
- `listen` (optional): native physical UDP socket bind address, default
  `:0` (ephemeral UDP port). No inbound network access to this port is
  required for basic relay connectivity, although NAT traversal benefits from
  inbound UDP.
- `low_bandwidth`: passed through to the native core.
- `moons`: optional private roots; `id` and `seed` are hexadecimal strings,
  not JS numbers. Orbit failures fail initialization.
- `library_path`: optional explicit native bridge library for development.
  Normal supported builds use their embedded/platform-integrated native
  artifact.

### First connection

1. Configure the ZeroTier network ID and start the node.
2. Authorize the newly created member in your network controller. The
   ZeroTier address is derived from the persistent identity in
   `<yuhaiin-data-dir>/zerotier/<identity>`.
3. Enable managed IP assignments on the controller. The first connection
   waits for the controller to supply network configuration and at least one
   local IPv4/IPv6 prefix; an unauthorised or unavailable network will return
   a descriptive error.
4. Access addresses or managed routes through this outbound. The in-memory
   Ethernet bridge uses ARP (IPv4) and NDP (IPv6), including queued packets
   awaiting neighbor resolution. No system interface or administrator
   privileges are necessary.

### Limitations and security

- The physical UDP underlay uses a dedicated OS socket and **cannot be chained
  through another outbound**. This is rejected explicitly instead of routing
  around a configured preceding proxy.
- The address and MTU come from the controller; the stack is replaced when
  those change. Existing TCP/UDP sessions cannot survive address replacement.
- Controller-assigned routes are scoped to the overlay; they are not applied to
  the host. Controller DNS settings are not automatically added to yuhaiin's
  resolver. ICMP `Ping` is not implemented.
- Managed IPv4/IPv6 traffic is supported, but this is not a general Ethernet
  tap/bridge: VLANs, arbitrary L2 protocols, and multicast service discovery
  across the IP stack are not guaranteed.
- Identity files include private identity state. Back them up securely and
  restrict access. They are written with `0600` permissions.
- Native bindings are compiled for Linux AMD64/ARM64, macOS AMD64/ARM64,
  Windows AMD64, and Android ARM64 **with CGO/NDK enabled**. FreeBSD, OpenBSD,
  unsupported architectures and CGO-disabled Android cross builds retain a
  protocol registration stub that explicitly returns an unsupported error.
- Native packaging matters: macOS requires a signed dylib installed with the
  application; Android ARM64 requires `libztgo.so` under
  `jniLibs/arm64-v8a/` during APK/AAR packaging. The ZeroTier Go binding
  does not extract a shared library to an unsafe path.

## Tests

```sh
go test ./pkg/contract/node ./pkg/net/proxy/zerotier
go test -race ./pkg/net/proxy/zerotier
```

The hermetic tests cover ARP request/reply and buffered IPv4 delivery, IPv6
neighbor solicitation/advertisement, 64-bit node/Moon configuration, and
bounded pending queues. They are **not proof of native peer interoperability**.
For complete validation, use `zerotier-go`'s official-controller real-link
integration tests and repeat a real TCP and UDP round trip through this
outbound on each target platform.

The native module's source and redistribution obligations are documented at
[zerotier-go](https://github.com/yuhaiin/zerotier-go). The external ZeroTier
controller is not embedded in yuhaiin.
