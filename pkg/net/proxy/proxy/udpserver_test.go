package proxy

import (
	"testing"
)

func TestUDPServer(t *testing.T) {
	s, err := NewUDPServer("127.0.0.1:1081", func(b []byte, p Proxy) ([]byte, error) { return nil, nil })
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
