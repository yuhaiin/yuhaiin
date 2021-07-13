package proxy

import (
	"testing"
)

func TestImplementUDPServer(t *testing.T) {
	var _ Proxy = new(UDPServer)
	var _ Server = new(UDPServer)
}

func TestUDPServer(t *testing.T) {
	s, err := NewUDPServer("127.0.0.1:1081")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	s.Close()
	//select {}
	s.SetServer("127.0.0.1:1082")
	s.Close()
	select {}
}
