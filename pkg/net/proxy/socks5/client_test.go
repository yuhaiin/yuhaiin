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

func TestUsernamePassword(t *testing.T) {
	ss, err := simple.NewServer(&listener.Inbound_Tcpudp{
		Tcpudp: &listener.Tcpudp{
			Host:    "0.0.0.0:1082",
			Control: listener.TcpUdpControl_tcp_udp_control_all,
		},
	})
	assert.NoError(t, err)
	defer ss.Close()

	accept, err := NewServer(&listener.Inbound_Socks5{
		Socks5: &listener.Socks5{
			Username: "test",
			Password: "test",
			Udp:      true,
		},
	})(ss)
	assert.NoError(t, err)
	defer accept.Close()

	go func() {
		for {

			conn, err := accept.AcceptStream()
			assert.NoError(t, err)

			t.Log(conn)

			go func() {
				buf := make([]byte, 1024)
				n, err := conn.Src.Read(buf)
				assert.NoError(t, err)
				t.Log(string(buf[:n]))
				conn.Src.Close()
			}()
		}
	}()

	go func() {
		for {
			conn, err := accept.AcceptPacket()
			assert.NoError(t, err)
			t.Log(conn, string(conn.Payload))
		}
	}()

	p := Dial("127.0.0.1", "1082", "test", "test")

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

	time.Sleep(time.Second * 2)
}

func TestSC(t *testing.T) {
	p := Dial("127.0.0.1", "1082", "username", "password")

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				assert.NoError(t, err)
				return p.Conn(ctx, ad)
			},
		},
	}

	resp, err := hc.Get("https://ip.sb")
	assert.NoError(t, err)
	defer resp.Body.Close()

	_, err = io.Copy(os.Stdout, resp.Body)
	assert.NoError(t, err)
}
