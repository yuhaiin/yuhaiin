package protocol

import (
	"bytes"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
	"slices"
	"sync"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks/core"
	ssrcipher "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/cipher"
	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

func testProtocolInfo(t *testing.T, name string) Protocol {
	t.Helper()
	c, err := ssrcipher.NewCipher("aes-128-cfb", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	return Protocol{Cipher: c, Auth: NewAuth(), Name: name, TcpMss: 1460, IV: make([]byte, c.IVSize())}
}

func TestConcurrentAuthIDs(t *testing.T) {
	a := NewAuth()
	const count = 500
	var wg sync.WaitGroup
	ids := make(chan uint64, count)
	for range count {
		wg.Go(func() {
			client, id := a.nextAuth()
			ids <- uint64(binary.LittleEndian.Uint32(client[:]))<<32 | uint64(id)
		})
	}
	wg.Wait()
	close(ids)
	seen := make(map[uint64]bool, count)
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate auth connection id %x", id)
		}
		seen[id] = true
	}
	if len(seen) != count {
		t.Fatalf("got %d identifiers, want %d", len(seen), count)
	}
}

func TestAESPacketTooShort(t *testing.T) {
	for _, name := range []string{"auth_aes128_md5", "auth_aes128_sha1"} {
		t.Run(name, func(t *testing.T) {
			p := ProtocolMethod[name](testProtocolInfo(t, name))
			for n := range 4 {
				if _, err := p.DecryptPacket(make([]byte, n)); !errors.Is(err, ssr.ErrAuthAES128DataLengthError) {
					t.Fatalf("length %d: expected length error, got %v", n, err)
				}
			}
		})
	}
}

func TestSHA1V4RejectsMalformedPadding(t *testing.T) {
	p := NewAuthSHA1v4(testProtocolInfo(t, "auth_sha1_v4"))
	frame := make([]byte, 12)
	binary.BigEndian.PutUint16(frame, uint16(len(frame)))
	binary.LittleEndian.PutUint16(frame[2:], uint16(ssr.CalcCRC32(frame, 2)))
	frame[4] = 250 // Valid Adler-32, but payload offset exceeds the frame.
	binary.LittleEndian.PutUint32(frame[len(frame)-4:], ssr.CalcAdler32(frame[:len(frame)-4]))
	var dst pool.Buffer
	if _, err := p.DecryptStream(&dst, frame); !errors.Is(err, ssr.ErrAuthSHA1v4DataLengthError) {
		t.Fatalf("expected invalid padding error, got %v", err)
	}
	if CheckAdler32(nil, 4) || CheckAdler32([]byte{1, 2, 3}, 3) {
		t.Fatal("short checksum input accepted")
	}
}

func TestOTAEmptyAndReadOnlyInput(t *testing.T) {
	p := NewVerifySHA1(testProtocolInfo(t, "verify_sha1"))
	var dst pool.Buffer
	if err := p.EncryptStream(&dst, nil); err != nil {
		t.Fatal(err)
	}
	source := []byte{1, 127, 0, 0, 1, 0, 80, 9, 8}
	copyOfSource := slices.Clone(source)
	if err := p.EncryptStream(&dst, source); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(source, copyOfSource) {
		t.Fatal("OTA encryption modified caller data")
	}
	if dst.Len() == 0 || dst.Bytes()[0]&oneTimeAuthMask == 0 {
		t.Fatal("missing OTA header flag")
	}
}

func TestAuthChainUDPPacket(t *testing.T) {
	for _, name := range []string{"auth_chain_a", "auth_chain_b"} {
		t.Run(name, func(t *testing.T) {
			p := ProtocolMethod[name](testProtocolInfo(t, name)).(*authChainA)
			payload := []byte("a packet with several bytes")
			saved := slices.Clone(payload)
			packet, err := p.EncryptPacket(payload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, saved) {
				t.Fatal("encryption modified source")
			}
			mac := p.hmac.HMAC(p.Key(), packet[len(packet)-8:len(packet)-5], nil)
			var rng ssr.Shift128plusContext
			padding := udpGetRandLength(mac, &rng)
			if len(packet) != len(payload)+padding+8 {
				t.Fatalf("packet length %d, want %d", len(packet), len(payload)+padding+8)
			}
			for i := range p.uid {
				if packet[len(packet)-5+i] != p.uid[i]^mac[i] {
					t.Fatal("incorrect obfuscated UID")
				}
			}
			if packet[len(packet)-1] != p.hmac.HMAC(p.userKey, packet[:len(packet)-1], nil)[0] {
				t.Fatal("incorrect packet tag")
			}
			key := core.KDF(base64.StdEncoding.EncodeToString(p.userKey)+base64.StdEncoding.EncodeToString(mac), 16)
			rc, err := rc4.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			decoded := make([]byte, len(payload))
			rc.XORKeyStream(decoded, packet[:len(payload)])
			if !bytes.Equal(decoded, payload) {
				t.Fatal("client packet payload does not decrypt")
			}

			// Build a server-to-client frame using the documented independent
			// seven-byte random field, then verify the decoder and its bounds.
			random := []byte{1, 2, 3, 4, 5, 6, 7}
			serverMAC := p.hmac.HMAC(p.Key(), random, nil)
			padding = udpGetRandLength(serverMAC, &rng)
			reply := make([]byte, len(payload)+padding+8)
			key = core.KDF(base64.StdEncoding.EncodeToString(p.userKey)+base64.StdEncoding.EncodeToString(serverMAC), 16)
			rc, err = rc4.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			rc.XORKeyStream(reply[:len(payload)], payload)
			copy(reply[len(reply)-8:], random)
			reply[len(reply)-1] = p.hmac.HMAC(p.userKey, reply[:len(reply)-1], nil)[0]
			got, err := p.DecryptPacket(reply)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("server packet decode: %q, %v", got, err)
			}
			for n := range 8 {
				if _, err := p.DecryptPacket(make([]byte, n)); !errors.Is(err, ssr.ErrAuthChainDataLengthError) {
					t.Fatalf("short packet length %d: %v", n, err)
				}
			}
			// Authentic tag but no space for the derived padding.
			short := make([]byte, 8)
			copy(short[:7], random)
			short[7] = p.hmac.HMAC(p.userKey, short[:7], nil)[0]
			if padding > 0 {
				if _, err := p.DecryptPacket(short); !errors.Is(err, ssr.ErrAuthChainDataLengthError) {
					t.Fatalf("bad padding: %v", err)
				}
			}
		})
	}
}

type testFrameProtocol struct{}

func (testFrameProtocol) EncryptStream(dst *pool.Buffer, data []byte) error {
	_ = dst.WriteByte(byte(len(data)))
	_, _ = dst.Write(data)
	return nil
}
func (testFrameProtocol) DecryptStream(dst *pool.Buffer, data []byte) (int, error) {
	consumed := 0
	for len(data) > 0 {
		frameLen := int(data[0])
		if len(data) < frameLen+1 {
			break
		}
		_, _ = dst.Write(data[1 : frameLen+1])
		consumed += frameLen + 1
		data = data[frameLen+1:]
	}
	return consumed, nil
}
func (testFrameProtocol) EncryptPacket(data []byte) ([]byte, error) { return data, nil }

func (testFrameProtocol) DecryptPacket(data []byte) ([]byte, error) { return data, nil }

func (testFrameProtocol) GetOverhead() int                          { return 0 }

type fragmentConn struct {
	io.Reader
	written  bytes.Buffer
	maxWrite int
}

func (c *fragmentConn) Write(p []byte) (int, error) {
	if c.maxWrite > 0 && len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	return c.written.Write(p)
}

func (c *fragmentConn) Close() error { return nil }


func (c *fragmentConn) LocalAddr() net.Addr { return nil }

func (c *fragmentConn) RemoteAddr() net.Addr { return nil }

func (c *fragmentConn) SetDeadline(time.Time) error { return nil }

func (c *fragmentConn) SetReadDeadline(time.Time) error { return nil }

func (c *fragmentConn) SetWriteDeadline(time.Time) error { return nil }

func TestStreamFramingAndShortWrite(t *testing.T) {
	raw := &fragmentConn{Reader: bytes.NewReader([]byte{5, 'h', 'e', 'l', 'l', 'o'}), maxWrite: 2}
	c := newConn(raw, testFrameProtocol{})
	out := make([]byte, 2)
	var result []byte
	for len(result) < 5 {
		n, err := c.Read(out)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, out[:n]...)
	}
	if string(result) != "hello" {
		t.Fatalf("read %q", result)
	}
	if n, err := c.Write([]byte("abcde")); err != nil || n != 5 {
		t.Fatalf("write: %d, %v", n, err)
	}
	if !bytes.Equal(raw.written.Bytes(), []byte{5, 'a', 'b', 'c', 'd', 'e'}) {
		t.Fatalf("short writes dropped bytes: %q", raw.written.Bytes())
	}
}

func TestStreamTruncatedFrame(t *testing.T) {
	c := newConn(&fragmentConn{Reader: bytes.NewReader([]byte{5, 'x'})}, testFrameProtocol{})
	if _, err := c.Read(make([]byte, 8)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected truncated ciphertext error, got %v", err)
	}
}
