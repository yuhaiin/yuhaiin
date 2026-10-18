// Package obfs implements the Hysteria 2 Salamander packet obfuscation.
package obfs

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"syscall"

	"golang.org/x/crypto/blake2b"
)

const saltSize = 8

// WrapPacketConnSalamander implements [salt:8][payload XOR BLAKE2b(PSK||salt)].
// This is obfuscation, not authenticated encryption.
func WrapPacketConnSalamander(conn net.PacketConn, password []byte) (net.PacketConn, error) {
	if len(password) < 4 { return nil, fmt.Errorf("hysteria2: salamander password too short") }
	c := &connWrapper{PacketConn: conn, keyInput: make([]byte, len(password)+saltSize), readBuf: make([]byte, 65535+saltSize)}
	copy(c.keyInput, password)
	if udp, ok := conn.(udpLike); ok { return &udpWrapper{connWrapper:c, udpLike:udp}, nil }
	return c, nil
}

type connWrapper struct {
	net.PacketConn
	readMu, writeMu sync.Mutex
	keyInput []byte
	readBuf []byte
}

func (c *connWrapper) key(salt []byte) [32]byte {
	copy(c.keyInput[len(c.keyInput)-saltSize:], salt)
	return blake2b.Sum256(c.keyInput)
}

func (c *connWrapper) ReadFrom(dst []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		n, addr, err := c.PacketConn.ReadFrom(c.readBuf)
		if err != nil { return 0, addr, err }
		if n <= saltSize || n-saltSize > len(dst) { continue }
		key := c.key(c.readBuf[:saltSize])
		for i := 0; i < n-saltSize; i++ { dst[i] = c.readBuf[i+saltSize] ^ key[i%len(key)] }
		return n-saltSize, addr, nil
	}
}

func (c *connWrapper) WriteTo(src []byte, addr net.Addr) (int, error) {
	if len(src) == 0 || len(src) > 65535-saltSize { return 0, fmt.Errorf("hysteria2: oversized salamander packet") }
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	out := make([]byte, len(src)+saltSize)
	if _, err := rand.Read(out[:saltSize]); err != nil { return 0, err }
	key := c.key(out[:saltSize])
	for i, v := range src { out[i+saltSize] = v ^ key[i%len(key)] }
	n, err := c.PacketConn.WriteTo(out, addr)
	if err != nil { return 0, err }
	if n != len(out) { return 0, fmt.Errorf("hysteria2: short salamander packet write") }
	return len(src), nil
}

type udpLike interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

type udpWrapper struct { *connWrapper; udpLike udpLike }
func (c *udpWrapper) SyscallConn() (syscall.RawConn, error) { return c.udpLike.SyscallConn() }
func (c *udpWrapper) SetReadBuffer(n int) error { return c.udpLike.SetReadBuffer(n) }
func (c *udpWrapper) SetWriteBuffer(n int) error { return c.udpLike.SetWriteBuffer(n) }
var _ net.PacketConn = (*connWrapper)(nil)
