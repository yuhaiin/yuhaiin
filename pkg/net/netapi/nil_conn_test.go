package netapi

import (
	"net"
	"testing"
)

func TestIsNilConn(t *testing.T) {
	var missing *net.TCPConn
	var c net.Conn = missing
	if !IsNilConn(c) || !IsNilConn(nil) {
		t.Fatal("nil TCP connections must be detected")
	}
	if IsNilConn(&net.TCPConn{}) {
		t.Fatal("non-nil TCP connection reported missing")
	}
}

func TestIsNilPacketConn(t *testing.T) {
	var missing *net.UDPConn
	var c net.PacketConn = missing
	if !IsNilPacketConn(c) || !IsNilPacketConn(nil) {
		t.Fatal("nil UDP connections must be detected")
	}
	if IsNilPacketConn(&net.UDPConn{}) {
		t.Fatal("non-nil UDP connection reported missing")
	}
}
