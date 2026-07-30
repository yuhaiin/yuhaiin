package aead

import (
	"bytes"
	"crypto/cipher"
	"net"
	"sync"
	"testing"
	"time"
)

type memoryPacket struct {
	data []byte
	addr net.Addr
}

type memoryPacketConn struct {
	reads  chan memoryPacket
	mu     sync.Mutex
	writes []memoryPacket
}

func (m *memoryPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	packet := <-m.reads
	return copy(p, packet.data), packet.addr, nil
}

func (m *memoryPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	m.mu.Lock()
	m.writes = append(m.writes, memoryPacket{data: append([]byte(nil), p...), addr: addr})
	m.mu.Unlock()
	return len(p), nil
}

func (m *memoryPacketConn) Close() error                     { return nil }
func (m *memoryPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (m *memoryPacketConn) SetDeadline(time.Time) error      { return nil }
func (m *memoryPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (m *memoryPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestMultiAuthPacketConnRepliesWithMatchedCredential(t *testing.T) {
	first, err := newAead(Chacha20poly1305, Salt([]byte("first-password")))
	if err != nil {
		t.Fatal(err)
	}
	second, err := newAead(Chacha20poly1305, Salt([]byte("second-password")))
	if err != nil {
		t.Fatal(err)
	}
	raw := &memoryPacketConn{reads: make(chan memoryPacket, 1)}
	conn := NewMultiAuthPacketConn(raw, []cipher.AEAD{first, second})
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	request := []byte("request")
	encoded, err := encryptPacket(make([]byte, second.NonceSize()+second.Overhead()+len(request)), request, second)
	if err != nil {
		t.Fatal(err)
	}
	raw.reads <- memoryPacket{data: encoded, addr: addr}

	decoded := make([]byte, 1024)
	n, gotAddr, err := conn.ReadFrom(decoded)
	if err != nil || !bytes.Equal(decoded[:n], request) || gotAddr.String() != addr.String() {
		t.Fatalf("ReadFrom() = %q, %v, %v", decoded[:n], gotAddr, err)
	}

	response := []byte("response")
	if _, err := conn.WriteTo(response, addr); err != nil {
		t.Fatal(err)
	}
	raw.mu.Lock()
	written := raw.writes[0].data
	raw.mu.Unlock()
	if plain, err := decryptPacket(append([]byte(nil), written...), second); err != nil || !bytes.Equal(plain, response) {
		t.Fatalf("response was not encrypted with matched credential: plain=%q err=%v", plain, err)
	}
	if _, err := decryptPacket(written, first); err == nil {
		t.Fatal("response unexpectedly decrypts with first credential")
	}
}
