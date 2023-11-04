package entity

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
	HandshakeServer(net.Conn) (net.Conn, error)
	HandshakeClient(net.Conn) (net.Conn, error)
	StreamHeader(buf *bytes.Buffer, addr netapi.Address)
	PacketHeader(*bytes.Buffer)
	ParseHeader(net.Conn) (Net, error)
}
