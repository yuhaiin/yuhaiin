package crypto

import (
	"bytes"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type Net byte

var (
	TCP Net = 66
	UDP Net = 77
)

func (n Net) Unknown() bool { return n != TCP && n != UDP }

type Handshaker interface {
	Handshake(net.Conn) (net.Conn, error)
	EncodeHeader(Net, *bytes.Buffer, netapi.Address)
	DecodeHeader(net.Conn) (Net, error)
}
