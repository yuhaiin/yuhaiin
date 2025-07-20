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
		wg.Add(1)

		go func() {
			defer wg.Done()

			password := make([]byte, rand.IntN(1024))
			_, err := io.ReadFull(crand.Reader, password)
			assert.NoError(t, err)

			dedata := make([]byte, rand.IntN(65535))
			_, err = io.ReadFull(crand.Reader, dedata)
			assert.NoError(t, err)

			buf := pool.NewBufferSize(pool.MaxSegmentSize)
			assert.NoError(t, EncodePacket(buf, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
				dedata, password, true))

			dedata, addr, err := DecodePacket(buf.Bytes(), password, true)
			assert.NoError(t, err)

			if !bytes.Equal(dedata, dedata) {
				t.Error("dedata not equal", addr)
				t.Fail()
			}
		}()
	}

	wg.Wait()
}

func TestEncode(t *testing.T) {
	password := []byte("testzxc")

	req := randSeq(rand.IntN(60000))
	buf := pool.NewBufferSize(pool.MaxSegmentSize)
	assert.NoError(t, EncodePacket(buf, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		req, password, true))

	// t.Log(buf.Bytes())

	data, addr, err := DecodePacket(buf.Bytes(), password, true)
	assert.NoError(t, err)

	if bytes.Equal(req, data) {
		t.Log("same", addr)
	}

	req = randSeq(rand.IntN(60000))
	buf = pool.NewBufferSize(pool.MaxSegmentSize)
	assert.NoError(t, EncodePacket(buf,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		req, password, true))

	data, addr, err = DecodePacket(buf.Bytes(), password, true)
	assert.NoError(t, err)

	if bytes.Equal(req, data) {
		t.Log("same", addr)
	}

	req = randSeq(rand.IntN(60000))
	buf = pool.NewBufferSize(pool.MaxSegmentSize)
	assert.NoError(t, EncodePacket(buf,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, req, password, false))

	data, addr, err = DecodePacket(buf.Bytes(), password, false)
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
