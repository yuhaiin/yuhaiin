# SSTP outbound

The client carries PPP over the Microsoft SSTP TLS connection and authenticates
with MS-CHAPv2.

```json
{
  "type": "sstp",
  "sstp": {
    "gateway": "vpn.example.com",
    "username": "alice",
    "password": "YOUR_SECRET",
    "insecure_skip_verify": false,
    "mtu": 1400
  }
}
```

`gateway`, `username`, and `password` are required. A gateway may include a
non-default port. `insecure_skip_verify` permits a self-signed TLS certificate;
the PPP handshake still verifies the server's MS-CHAPv2 response. `mtu` is
optional and limits the server-recommended inner MTU.

## Real SoftEther test and benchmark

The Podman fixture starts SoftEther VPN Server 4.43 with its SSTP listener and
an echo service in the same container network namespace. It checks login,
rejected credentials, reconnect after close, and TCP and UDP echo through the
PPP data path. Run the real-server checks and three samples of each benchmark
with:

```sh
python3 scripts/bench/sstp/run.py --runtime podman --benchmark
```

The benchmark reports connection setup plus TCP and UDP echo performance over
local Podman networking; it does not measure remote Internet throughput. The
TCP rate counts one-way application bytes while the echo sends the same bytes
back through the tunnel. The ephemeral server uses a self-signed certificate,
so the test opts out of TLS certificate verification only for that throwaway
fixture.

## Rootless SSTP server

See [SSTP inbound (rootless)](SERVER.md) for server configuration, authentication requirements, limitations, and the in-memory forwarding architecture.
