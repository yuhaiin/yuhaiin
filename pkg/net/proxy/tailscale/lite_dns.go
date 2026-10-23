package tailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"

	lite "github.com/yuhaiin/tailscale-lite"
)

// The full Tailscale DNS manager, including authoritative MagicDNS, PTR,
// Split DNS and upstream forwarding, runs inside the lite engine. Keep one
// well-defined gateway for both wire transports.
var errTailscaleDNSUnavailable = errors.New("tailscale: DNS manager unavailable")

func liteDNSQuery(ctx context.Context, client *lite.Client, packet []byte) ([]byte, error) {
	if client == nil {
		return nil, errTailscaleDNSUnavailable
	}
	return client.QueryDNS(ctx, packet, "udp", netip.AddrPort{})
}

func serveLiteDNS(conn net.Conn, client *lite.Client) {
	if client == nil {
		return
	}
	_ = client.HandleDNSConn(conn, netip.AddrPort{})
}
