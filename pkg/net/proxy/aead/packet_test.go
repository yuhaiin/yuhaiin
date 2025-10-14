package aead

import (
	"context"
	crand "crypto/rand"
	"io"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/proto"
)

func TestEncodePacket(t *testing.T) {
	for _, method := range [...]Aead{
		Chacha20poly1305,
		XChacha20poly1305,
	} {
		password := make([]byte, rand.IntN(60000))
		_, _ = io.ReadFull(crand.Reader, password)
		auth, err := newAead(method, password)
		assert.NoError(t, err)

		data := make([]byte, rand.IntN(60000))
		_, _ = io.ReadFull(crand.Reader, data)

		buf := make([]byte, auth.NonceSize()+auth.Overhead()+len(data))
		encode := encodePacket(buf, data, auth)

		decoded, err := decodePacket(encode, auth)
		assert.NoError(t, err)
		assert.MustEqual(t, data, decoded)
	}
}

func BenchmarkEncodePacket(b *testing.B) {
	password := make([]byte, rand.IntN(60000))
	_, _ = io.ReadFull(crand.Reader, password)

	run := func(b *testing.B, method Aead, size int) {
		auth, err := newAead(method, password)
		assert.NoError(b, err)

		data := make([]byte, size)
		_, _ = io.ReadFull(crand.Reader, data)

		buf := make([]byte, auth.NonceSize()+auth.Overhead()+len(data))
		encode := encodePacket(buf, data, auth)

		decoded, err := decodePacket(encode, auth)
		assert.NoError(b, err)
		assert.MustEqual(b, data, decoded)
	}

	b.Run("chacha20", func(b *testing.B) {
		for i := 1; b.Loop(); i++ {
			run(b, Chacha20poly1305, i)
		}
	})

	b.Run("xchacha20", func(b *testing.B) {
		for i := 1; b.Loop(); i++ {
			run(b, XChacha20poly1305, i)
		}
	})
}

func TestPacket(t *testing.T) {
	s, err := fixed.NewServer(listener.Tcpudp_builder{
		Host:    proto.String(":12345"),
		Control: listener.TcpUdpControl_disable_tcp.Enum(),
	}.Build())
	assert.NoError(t, err)

	as, err := NewServer(listener.Aead_builder{
		Password:     proto.String("123456"),
		CryptoMethod: protocol.AeadCryptoMethod_XChacha20Poly1305.Enum(),
	}.Build(), s)
	assert.NoError(t, err)

	pc, err := as.Packet(context.Background())
	assert.NoError(t, err)
	defer pc.Close()

	go func() {
		var buf [1024]byte
		for {
			n, addr, err := pc.ReadFrom(buf[:])
			if err != nil {
				break
			}

			t.Log("read from", addr, "data", string(buf[:n]))
		}
	}()

	fp, err := fixed.NewClient(protocol.Fixed_builder{
		Host: proto.String("127.0.0.1"),
		Port: proto.Int32(12345),
	}.Build(), nil)
	assert.NoError(t, err)
	defer fp.Close()

	ac, err := NewClient(protocol.Aead_builder{
		Password:     proto.String("123456"),
		CryptoMethod: protocol.AeadCryptoMethod_XChacha20Poly1305.Enum(),
	}.Build(), fp)
	assert.NoError(t, err)
	defer ac.Close()

	pc, err = ac.PacketConn(context.Background(), netapi.EmptyAddr)
	assert.NoError(t, err)
	defer pc.Close()

	pc.WriteTo([]byte("hello"), netapi.EmptyAddr)

	time.Sleep(time.Second)
}
