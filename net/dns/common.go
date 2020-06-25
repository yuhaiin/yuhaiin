package dns

import "net"

type DNS interface {
	SetServer(host string)
	SetSubnet(subnet net.IP)
	Search(domain string) ([]net.IP, error)
}
