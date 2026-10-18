package obfs

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestSalamanderUDP(t *testing.T) {
	s, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	client, err := WrapPacketConnSalamander(c, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := WrapPacketConnSalamander(s, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("native HY2 salamander")
	if n, err := client.WriteTo(payload, s.LocalAddr()); err != nil || n != len(payload) {
		t.Fatalf("send %d, %v", n, err)
	}
	var buf [2048]byte
	n, addr, err := server.ReadFrom(buf[:])
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("receive %d, %v", n, err)
	}
	if _, err := server.WriteTo(payload, addr); err != nil {
		t.Fatal(err)
	}
	n, _, err = client.ReadFrom(buf[:])
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("reply %d, %v", n, err)
	}
}
func TestPasswordTooShort(t *testing.T) {
	if _, err := WrapPacketConnSalamander(nil, []byte("bad")); err == nil {
		t.Fatal("accepted weak password")
	}
}
