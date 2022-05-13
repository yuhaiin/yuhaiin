package vmess

import (
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

// Addr is vmess addr
type Addr []byte

// Port is vmess addr port
type Port uint16

// ParseAddr parses the address in string s
func ParseAddr(s proxy.Address) (Atyp, Addr, Port, error) {
	var atyp Atyp
	var addr Addr

	if s.Type() == proxy.DOMAIN {
		if len(s.Hostname()) > 255 {
			return 0, nil, 0, fmt.Errorf("addr length over 255")
		}
		atyp = AtypDomain
		addr = append([]byte{byte(len(s.Hostname()))}, []byte(s.Hostname())...)
	}

	ip := s.IP()
	if ip == nil {
		return 0, nil, 0, fmt.Errorf("invalid addr")
	}

	if ip4 := ip.To4(); ip4 != nil {
		addr = make([]byte, net.IPv4len)
		atyp = AtypIP4
		copy(addr[:], ip4)
	} else {
		addr = make([]byte, net.IPv6len)
		atyp = AtypIP6
		copy(addr[:], ip)
	}

	return atyp, addr, Port(s.Port().Port()), nil
}
