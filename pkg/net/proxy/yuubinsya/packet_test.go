package yuubinsya

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/crypto"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/plain"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
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

			auth, err := crypto.GetAuth(password)
			assert.NoError(t, err)

			buf := pool.NewBufferSize(pool.MaxSegmentSize)
			assert.NoError(t, types.EncodePacket(buf, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
				dedata, auth, true))

			dedata, addr, err := types.DecodePacket(buf.Bytes(), auth, true)
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
	auth, err := crypto.GetAuth([]byte("testzxc"))
	assert.NoError(t, err)

	req := randSeq(rand.IntN(60000))
	buf := pool.NewBufferSize(pool.MaxSegmentSize)
	assert.NoError(t, types.EncodePacket(buf, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		req, auth, true))

	// t.Log(buf.Bytes())

	data, addr, err := types.DecodePacket(buf.Bytes(), auth, true)
	assert.NoError(t, err)

	if bytes.Equal(req, data) {
		t.Log("same", addr)
	}

	plainauth := plain.NewAuth([]byte{1, 2, 3, 4, 5})

	req = randSeq(rand.IntN(60000))
	buf = pool.NewBufferSize(pool.MaxSegmentSize)
	assert.NoError(t, types.EncodePacket(buf,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		req, plainauth, true))

	data, addr, err = types.DecodePacket(buf.Bytes(), plainauth, true)
	assert.NoError(t, err)

	if bytes.Equal(req, data) {
		t.Log("same", addr)
	}

	req = randSeq(rand.IntN(60000))
	buf = pool.NewBufferSize(pool.MaxSegmentSize)
	assert.NoError(t, types.EncodePacket(buf,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, req, nil, false))

	data, addr, err = types.DecodePacket(buf.Bytes(), nil, false)
	assert.NoError(t, err)

	if bytes.Equal(req, data) {
		t.Log("same", addr)
	}
}

func TestPacket(t *testing.T) {
	lis, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer lis.Close()

	auth := plain.NewAuth([]byte("telnoinnoijuhbbikjonkndnfioe439423fldfksdjf9034jpjffjst"))

	data := randSeq(rand.IntN(60000))

	go StartUDPServer(lis, func(p *netapi.Packet) error {
		_, err := p.WriteBack(p.Payload, p.Src)

		t.Log(len(p.Payload), bytes.Equal(data, p.Payload), p.Dst.String(), p.Src.String(), err)

		return nil
	}, auth, true)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer client.Close()

	cc := NewAuthPacketConn(client).WithTarget(lis.LocalAddr()).WithAuth(auth).WithPrefix(true)

	go func() {
		for {
			rdata := make([]byte, 65536)
			n, addr, err := cc.ReadFrom(rdata)
			assert.NoError(t, err)

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
