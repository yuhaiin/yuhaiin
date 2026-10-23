package tailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"

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

// resolveLiteDNSName resolves only through this Tailnet's control-configured
// DNS manager. The returned IP must still pass the caller's Tailnet route
// policy; DNS resolution alone never authorizes a system-network dial.
func resolveLiteDNSName(ctx context.Context, client *lite.Client, hostname string) ([]netip.Addr, error) {
	name := strings.TrimSuffix(hostname, ".") + "."
	var addresses []netip.Addr
	var errorsSeen []error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := netapi.NewDNSMsg(netapi.DNSQuestion{Name: name, Qtype: qtype, Qclass: dns.ClassINET})
		msg.Response = false
		msg.ID = uint16(qtype)
		if err := msg.Pack(); err != nil {
			return nil, err
		}
		wire, err := client.QueryDNS(ctx, msg.Data, "udp", netip.AddrPort{})
		if err != nil {
			errorsSeen = append(errorsSeen, err)
			continue
		}
		var reply dns.Msg
		reply.Data = wire
		if err := reply.Unpack(); err != nil {
			errorsSeen = append(errorsSeen, err)
			continue
		}
		if reply.ID != msg.ID || reply.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range reply.Answer {
			switch record := rr.(type) {
			case *dns.A:
				if record.Addr.Is4() {
					addresses = append(addresses, record.Addr)
				}
			case *dns.AAAA:
				if record.Addr.Is6() {
					addresses = append(addresses, record.Addr)
				}
			}
		}
	}
	if len(addresses) != 0 {
		return addresses, nil
	}
	if len(errorsSeen) != 0 {
		return nil, errors.Join(errorsSeen...)
	}
	return nil, errors.New("tailscale: DNS name has no routable IP records")
}
