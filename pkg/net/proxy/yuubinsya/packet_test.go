package yuubinsya

import (
	"bytes"
	crand "crypto/rand"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.IntN(len(letters))]
	}
	return b
}

func TestENDcode(t *testing.T) {
	wg := sync.WaitGroup{}
	for range 100 {
		wg.Go(func() {
			password := make([]byte, rand.IntN(1024))
			_, err := io.ReadFull(crand.Reader, password)
			assert.NoError(t, err)

			plaintext := make([]byte, rand.IntN(60000))
			_, err = io.ReadFull(crand.Reader, plaintext)
			assert.NoError(t, err)

			buf := pool.GetBytes(pool.MaxSegmentSize)
			encoded, err := EncodePacket(buf,
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
				plaintext, password, true)
			assert.NoError(t, err)

			dedata, addr, err := DecodePacket(encoded, password, true)
			assert.NoError(t, err)

			if !bytes.Equal(plaintext, dedata) {
				t.Error("dedata not equal", addr)
				t.Fail()
			}
		})
	}

	wg.Wait()
}

func TestEncode(t *testing.T) {
	password := []byte("testzxc")

	req := randSeq(rand.IntN(60000))
	buf := pool.GetBytes(pool.MaxSegmentSize)
	encoded, err := EncodePacket(buf, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		req, password, true)
	assert.NoError(t, err)

	// t.Log(buf.Bytes())

	data, addr, err := DecodePacket(encoded, password, true)
	assert.NoError(t, err)

	if bytes.Equal(req, data) {
		t.Log("same", addr)
	}

	req = randSeq(rand.IntN(60000))
	buf = pool.GetBytes(pool.MaxSegmentSize)
	encoded, err = EncodePacket(buf,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		req, password, true)
	assert.NoError(t, err)

	data, addr, err = DecodePacket(encoded, password, true)
	assert.NoError(t, err)

	if bytes.Equal(req, data) {
		t.Log("same", addr)
	}

	req = randSeq(rand.IntN(60000))
	buf = pool.GetBytes(pool.MaxSegmentSize)
	encoded, err = EncodePacket(buf,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, req, password, false)
	assert.NoError(t, err)

	data, addr, err = DecodePacket(encoded, password, false)
	assert.NoError(t, err)

	if bytes.Equal(req, data) {
		t.Log("same", addr)
	}
}

func TestPacket(t *testing.T) {
	lis, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer lis.Close()

	data := randSeq(rand.IntN(2500))

	go func() {
		_ = (&UDPServer{
			PacketConn: lis,
			Handler: func(p *netapi.Packet) {
				_, err := p.WriteBack(p.GetPayload(), p.Src())
				t.Log(len(p.GetPayload()), bytes.Equal(data, p.GetPayload()), p.Dst().String(), p.Src().String(), err)
			},
			Prefix: true,
		}).Serve()
	}()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer client.Close()

	cc := NewAuthPacketConn(client).WithRealTarget(lis.LocalAddr()).WithSocks5Prefix(true)

	go func() {
		for {
			rdata := make([]byte, 65536)
			n, addr, err := cc.ReadFrom(rdata)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					assert.NoError(t, err)
				}
				continue
			}

			t.Log(n, addr, bytes.Equal(rdata[:n], data))
		}
	}()

	for range 5 {
		go func() {
			_, err := cc.WriteTo(data, lis.LocalAddr())
			assert.NoError(t, err)
		}()
	}

	time.Sleep(time.Second * 3)
}

func FuzzDecodePacket(t *testing.F) {
	src, err := EncodePacket(make([]byte, 65535),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, []byte("test"), []byte("test"), true)
	assert.NoError(t, err)
	src2, err := EncodePacket(make([]byte, 65535),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1234}, []byte("test2"), []byte("test2"), false)
	assert.NoError(t, err)
	src3, err := EncodePacket(make([]byte, 65535),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 1234}, []byte("test3"), []byte("test3"), true)
	assert.NoError(t, err)

	random1, random2, random3 := make([]byte, rand.IntN(65535)), make([]byte, rand.IntN(65535)), make([]byte, rand.IntN(65535))
	_, err = io.ReadFull(crand.Reader, random1)
	assert.NoError(t, err)
	_, err = io.ReadFull(crand.Reader, random2)
	assert.NoError(t, err)
	_, err = io.ReadFull(crand.Reader, random3)
	assert.NoError(t, err)

	t.Add(src, []byte("test"), true)
	t.Add(src2, []byte("test2"), false)
	t.Add([]byte{}, []byte("test"), true)
	t.Add([]byte("garbage"), []byte("test"), false)
	t.Add([]byte{0x00, 0x01, 0x02}, []byte("x"), true)
	t.Add(src3, []byte("test3"), true)
	t.Add(random1, []byte("test"), true)
	t.Add(random2, []byte("test2"), false)
	t.Add(random3, []byte("test3"), true)

	t.Fuzz(func(t *testing.T, data, password []byte, prefix bool) {
		t.Log(prefix)
		data, addr, err := DecodePacket(data, password, prefix)
		t.Log(string(data), addr, err)
	})
}
