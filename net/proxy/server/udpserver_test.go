package proxy

import (
	"net"
	"testing"
)

func TestUDPServer(t *testing.T) {
	s, err := NewUDPServer("127.0.0.1:1081", func(from net.PacketConn, remoteAddr net.Addr, data []byte, udpConn func(string) (net.PacketConn, error)) {
	})
	if err != nil {
		t.Error(err)
	}
	//s.Close()
	//select {}
	s.UpdateListen("127.0.0.1:1082")
	//s.Close()
	select {}
}
