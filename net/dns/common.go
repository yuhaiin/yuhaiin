package dns

import "net"

type DNS interface {
	SetProxy(proxy func(addr string) (net.Conn, error))
	SetServer(host string)
	SetSubnet(subnet net.IP)
	GetSubnet() net.IP
	Search(domain string) ([]net.IP, error)
}
