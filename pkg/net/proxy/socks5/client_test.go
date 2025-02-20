package socks5

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/proto"
)

func TestUDP(t *testing.T) {
	p := Dial("127.0.0.1", "1080", "", "")

	packet, err := p.PacketConn(context.TODO(), netapi.ParseAddressPort("udp", "0.0.0.0", 0))
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

type handler struct {
	t *testing.T
}

func (h *handler) HandleStream(conn *netapi.StreamMeta) {
	h.t.Log(conn)

	go func() {
		buf := make([]byte, 1024)
		n, err := conn.Src.Read(buf)
		assert.NoError(h.t, err)
		h.t.Log(string(buf[:n]))
		conn.Src.Close()
	}()
}

func (h *handler) HandlePacket(conn *netapi.Packet) {
	h.t.Log(conn, string(conn.GetPayload()))

	conn.WriteBack.WriteBack(conn.GetPayload(), conn.Src)
}

func TestUsernamePassword(t *testing.T) {
	ss, err := simple.NewServer(listener.Tcpudp_builder{
		Host:    proto.String("0.0.0.0:1083"),
		Control: listener.TcpUdpControl_tcp_udp_control_all.Enum(),
	}.Build())
	assert.NoError(t, err)
	defer ss.Close()

	accept, err := NewServer(listener.Socks5_builder{
		Username: proto.String("test"),
		Password: proto.String("test"),
		Udp:      proto.Bool(true),
	}.Build(), ss, &handler{t})
	assert.NoError(t, err)
	defer accept.Close()

	p := Dial("127.0.0.1", "1083", "test", "test")

	stream, err := p.Conn(context.TODO(), netapi.ParseAddressPort("tcp", "www.google.com", 443))
	assert.NoError(t, err)
	defer stream.Close()

	_, err = stream.Write([]byte("GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"))
	assert.NoError(t, err)

	packet, err := p.PacketConn(context.TODO(), netapi.ParseAddressPort("udp", "0.0.0.0", 0))
	assert.NoError(t, err)
	defer packet.Close()

	_, err = packet.WriteTo([]byte("GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"), &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	assert.NoError(t, err)

	data := make([]byte, 1024)
	n, src, err := packet.ReadFrom(data)
	assert.NoError(t, err)

	t.Log("read packet from", src, "data:", string(data[:n]))

	time.Sleep(time.Second * 2)
}

func TestSC(t *testing.T) {
	p := Dial("127.0.0.1", "1082", "", "")

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				assert.NoError(t, err)
				return p.Conn(ctx, ad)
			},
		},
	}

	resp, err := hc.Get("http://ip.sb")
	assert.NoError(t, err)
	defer resp.Body.Close()

	_, err = io.Copy(os.Stdout, resp.Body)
	assert.NoError(t, err)
}
