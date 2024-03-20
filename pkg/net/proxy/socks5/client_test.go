package socks5

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestUDP(t *testing.T) {
	p := Dial("127.0.0.1", "1080", "", "")

	packet, err := p.PacketConn(context.TODO(), netapi.ParseAddressPort(statistic.Type_udp, "0.0.0.0", netapi.EmptyPort))
	assert.NoError(t, err)
	defer packet.Close()

	req := []byte{46, 230, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 7, 98, 114, 111, 119, 115, 101, 114, 4, 112, 105, 112, 101, 4, 97, 114, 105, 97, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 12, 0, 8, 0, 8, 0, 1, 22, 0, 223, 5, 4, 0}

	_, err = packet.WriteTo(req, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53})
	assert.NoError(t, err)

	_, err = packet.WriteTo(req, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	assert.NoError(t, err)

	buf := make([]byte, nat.MaxSegmentSize)

	for {
		_ = packet.SetReadDeadline(time.Now().Add(time.Second * 5))

		n, src, err := packet.ReadFrom(buf)
		assert.NoError(t, err)

		t.Log("read from", src, "data:", n)
	}
}
