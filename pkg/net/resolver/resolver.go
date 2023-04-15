package resolver

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"golang.org/x/net/dns/dnsmessage"
)

var Bootstrap dns.DNS = &System{}

type System struct{ DisableIPv6 bool }

func (d *System) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	var network string
	if d.DisableIPv6 {
		network = "ip4"
	} else {
		network = "ip"
	}
	return net.DefaultResolver.LookupIP(ctx, network, domain)
}

func (d *System) Record(ctx context.Context, domain string, t dnsmessage.Type) ([]net.IP, uint32, error) {
	var req string
	if t == dnsmessage.TypeAAAA {
		req = "ip6"
	} else {
		req = "ip4"
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, req, domain)
	if err != nil {
		return nil, 0, err
	}

	return ips, 60, nil
}

func (d *System) Close() error { return nil }
func (d *System) Do(context.Context, string, []byte) ([]byte, error) {
	return nil, fmt.Errorf("system dns not support")
}
func LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	return Bootstrap.LookupIP(ctx, domain)
}

func ResolveUDPAddr(ctx context.Context, address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", address)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		x, err := Bootstrap.LookupIP(ctx, host)
		if err != nil {
			return nil, err
		}

		ip = x[rand.Intn(len(x))]
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", port)
	}
	return &net.UDPAddr{IP: ip, Port: p}, nil
}
