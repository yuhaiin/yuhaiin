package vmess

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
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

type address struct{ netapi.Address }

func (a address) Type() Atyp {
	if a.IsFqdn() {
		return AtypDomain
	}

	if a.AddrPort(context.Background()).V.Addr().Is6() {
		return AtypIP6
	}

	return AtypIP4
}

func (a address) Bytes() []byte {

	if a.IsFqdn() {
		return append([]byte{byte(len(a.Hostname()))}, []byte(a.Hostname())...)
	}

	return a.AddrPort(context.Background()).V.Addr().AsSlice()
}
