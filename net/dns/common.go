package dns

import "net"

type DNS interface {
	SetProxy(proxy func(addr string) (net.Conn, error))
	SetServer(host string)
	GetServer() string
	SetSubnet(subnet *net.IPNet)
	GetSubnet() *net.IPNet
	Search(domain string) ([]net.IP, error)
}
