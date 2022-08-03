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

func (d *System) LookupIP(domain string) ([]net.IP, error) {
	var network string
	if d.DisableIPv6 {
		network = "ip4"
	} else {
		network = "ip"
	}
	return net.DefaultResolver.LookupIP(context.TODO(), network, domain)
}

func (d *System) Record(domain string, t dnsmessage.Type) (dns.IPResponse, error) {
	var req string
	if t == dnsmessage.TypeAAAA {
		req = "ip6"
	} else {
		req = "ip4"
	}

	ips, err := net.DefaultResolver.LookupIP(context.TODO(), req, domain)
	if err != nil {
		return nil, err
	}

	return dns.NewIPResponse(ips, 600), nil
}

func (d *System) Close() error                 { return nil }
func (d *System) Do([]byte) ([]byte, error)    { return nil, fmt.Errorf("system dns not support") }
func LookupIP(domain string) ([]net.IP, error) { return Bootstrap.LookupIP(domain) }

func ResolveUDPAddr(address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", address)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		x, err := Bootstrap.LookupIP(host)
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
