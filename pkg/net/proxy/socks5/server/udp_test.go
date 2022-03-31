package socks5server

import (
	"net"
	"testing"

	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
)

func TestServer_UDP2(t *testing.T) { // make a writer and write to dst
	targetUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", "1081"))
	if err != nil {
		t.Error(err)
	}
	target, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0}, targetUDPAddr)
	if err != nil {
		t.Error(err)
	}

	//conn,err := net.Dial("udp",net.JoinHostPort("127.0.0.1","1081"))
	//if err != nil{
	//	t.Error(err)
	//}

	z, _ := s5c.ParseAddr("1.1.1.1:53")
	x := append([]byte{0, 0, 0}, z...)

	//conn.Write(x)

	if _, err = target.Write(x); err != nil {
		t.Error(err)
	}
	b := make([]byte, 3*0x400)
	n, _ := target.Read(b[:])
	t.Log(b[:n])
	//if _,err = target.Read(b[:]); err != nil{
	//	t.Error(err)
	//}
	//t.Log(b)
}
