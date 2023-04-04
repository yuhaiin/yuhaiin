package vmess

import (
	"context"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

// Atyp is vmess addr type
type Atyp byte

// Atyp
const (
	AtypErr    Atyp = 0
	AtypIP4    Atyp = 1
	AtypDomain Atyp = 2
	AtypIP6    Atyp = 3
)

type address struct {
	atyp Atyp
	addr []byte
	proxy.Address
}

// ParseAddr parses the address in string s
func ParseAddr(s proxy.Address) (address, error) {
	var atyp Atyp
	var addr []byte

	if s.Type() == proxy.DOMAIN {
		atyp = AtypDomain
		addr = make([]byte, len(s.Hostname())+1)
		addr[0] = byte(len(s.Hostname()))
		copy(addr[1:], s.Hostname())
	} else {
		ip, err := s.IP(context.TODO())
		if err != nil {
			return address{}, fmt.Errorf("invalid addr: %w", err)
		}

		if ip4 := ip.To4(); ip4 != nil {
			addr = make([]byte, net.IPv4len)
			atyp = AtypIP4
			copy(addr[:], ip4)
		} else {
			addr = make([]byte, net.IPv6len)
			atyp = AtypIP6
			copy(addr[:], ip.To16())
		}
	}

	return address{atyp, addr, s}, nil
}
