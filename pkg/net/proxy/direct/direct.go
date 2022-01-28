package direct

import (
	"net"
	"time"
)

type Direct struct {
	dialer *net.Dialer
}

func NewDirect(dialer *net.Dialer) *Direct {
	d := &Direct{}

	if dialer != nil {
		d.dialer = dialer
	} else {
		d.dialer = &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
	}

	return d
}

func (d *Direct) Conn(s string) (net.Conn, error) {
	return d.dialer.Dial("tcp", s)
}

func (d *Direct) PacketConn(string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}
