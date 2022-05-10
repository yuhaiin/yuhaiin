package resolver

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
)

var Bootstrap dns.DNS = &System{}

type System struct{}

func (d *System) LookupIP(domain string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(context.TODO(), "ip4", domain)
}
func (d *System) Close() error { return nil }

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
