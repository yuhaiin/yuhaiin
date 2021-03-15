package proxy

import (
	"net"
	"testing"
)

func TestNew(t *testing.T) {
	s, err := NewTCPServer("127.0.0.1:1081", func(net.Conn, func(string) (net.Conn, error)) {})
	if err != nil {
		t.Error(err)
	}
	//s.Close()
	//select {}
	s.UpdateListen("127.0.0.1:1082")
	//s.Close()
	select {}
}
