package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	mrandv1 "math/rand"
	mrand "math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/nettest"
	"google.golang.org/protobuf/proto"
)

var cert = []byte(`-----BEGIN CERTIFICATE-----
MIIDJTCCAsqgAwIBAgIUUpPvsEwqcqRR08HfXOyGfAlWvKowCgYIKoZIzj0EAwIw
gY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTgwNgYDVQQL
Ey9DbG91ZEZsYXJlIE9yaWdpbiBTU0wgRUNDIENlcnRpZmljYXRlIEF1dGhvcml0
eTAeFw0yMzAyMDcxMjU5MDBaFw0zODAyMDMxMjU5MDBaMGIxGTAXBgNVBAoTEENs
b3VkRmxhcmUsIEluYy4xHTAbBgNVBAsTFENsb3VkRmxhcmUgT3JpZ2luIENBMSYw
JAYDVQQDEx1DbG91ZEZsYXJlIE9yaWdpbiBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABMDa0LxwazPtFxCxV297AGF1JAQTWXLbwxB8aQae+f9x
mFRypG3yp9Ey3vrL0ASF/gqg5HLNDx4k5d4xwQes3DqjggEuMIIBKjAOBgNVHQ8B
Af8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwHQYDVR0OBBYEFG1FazlD7aG2z4tkOjF8gJ85e1L2MB8GA1UdIwQYMBaA
FIUwXTsqcNTt1ZJnB/3rObQaDjinMEQGCCsGAQUFBwEBBDgwNjA0BggrBgEFBQcw
AYYoaHR0cDovL29jc3AuY2xvdWRmbGFyZS5jb20vb3JpZ2luX2VjY19jYTAnBgNV
HREEIDAegg4qLjEzNTQ3OTgyLnh5eoIMMTM1NDc5ODIueHl6MDwGA1UdHwQ1MDMw
MaAvoC2GK2h0dHA6Ly9jcmwuY2xvdWRmbGFyZS5jb20vb3JpZ2luX2VjY19jYS5j
cmwwCgYIKoZIzj0EAwIDSQAwRgIhAMDsQBnXncmISk0sqz7t+P2Qj/b1dbnTxdWH
S99Gg9cvAiEAyJV2fBIr8w7LWkv7AIws2LebiNdhbQMdqmIlxWx1YI8=
-----END CERTIFICATE-----
`)

var key = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfFPJ3xA3HtR6OR11
6b4x9zUqAB1JiCFWcnSm5SNEHuyhRANCAATA2tC8cGsz7RcQsVdvewBhdSQEE1ly
28MQfGkGnvn/cZhUcqRt8qfRMt76y9AEhf4KoORyzQ8eJOXeMcEHrNw6
-----END PRIVATE KEY-----
`)

func TestConn(t *testing.T) {
	t.Run("test close", func(t *testing.T) {
		s, err := NewServer(config.Quic_builder{
			Host: proto.String("127.0.0.1:0"),
			Tls: node.TlsServerConfig_builder{
				Certificates: []*node.Certificate{
					node.Certificate_builder{
						Cert: cert,
						Key:  key,
					}.Build(),
				},
			}.Build(),
		}.Build())
		assert.NoError(t, err)
		defer s.Close()

		server := make(chan net.Conn)

		go func() {
			for {
				conn, err := s.Accept()
				if err != nil {
					break
				}

				server <- conn
			}
		}()

		qc, err := NewClient(node.Quic_builder{
			Host: proto.String(s.Addr().String()),
			Tls: node.TlsConfig_builder{
				Enable:             proto.Bool(true),
				InsecureSkipVerify: proto.Bool(true),
			}.Build(),
		}.Build(), nil)
		assert.NoError(t, err)

		conn, err := qc.Conn(context.TODO(), netapi.EmptyAddr)
		assert.NoError(t, err)

		// fmt.Println("conn", conn.RemoteAddr())

		n, err := conn.Write([]byte("hello"))
		assert.NoError(t, err)

		src := <-server

		// fmt.Println("src", src.RemoteAddr(), conn.RemoteAddr())

		_, err = src.Read(make([]byte, n))
		assert.NoError(t, err)

		conn.Close()

		_, err = conn.Read(make([]byte, 1024))
		assert.Error(t, err)

		defer src.Close()
		defer conn.Close()
		defer s.Close()
	})

	t.Run("test io", func(t *testing.T) {
		s, err := NewServer(config.Quic_builder{
			Host: proto.String("127.0.0.1:0"),
			Tls: node.TlsServerConfig_builder{
				Certificates: []*node.Certificate{
					node.Certificate_builder{
						Cert: cert,
						Key:  key,
					}.Build(),
				},
			}.Build(),
		}.Build())
		assert.NoError(t, err)
		defer s.Close()

		server := make(chan net.Conn)

		go func() {
			for {
				conn, err := s.Accept()
				if err != nil {
					break
				}

				server <- conn
			}
		}()

		qc, err := NewClient(node.Quic_builder{
			Host: proto.String(s.Addr().String()),
			Tls: node.TlsConfig_builder{
				Enable:             proto.Bool(true),
				InsecureSkipVerify: proto.Bool(true),
			}.Build(),
		}.Build(), nil)
		assert.NoError(t, err)

		conn, err := qc.Conn(context.TODO(), netapi.EmptyAddr)
		assert.NoError(t, err)

		// fmt.Println("conn", conn.RemoteAddr())

		n, err := conn.Write([]byte("hello"))
		assert.NoError(t, err)

		src := <-server

		_, err = src.Read(make([]byte, n))
		assert.NoError(t, err)

		// fmt.Println("src", src.RemoteAddr(), conn.RemoteAddr())

		defer src.Close()
		defer conn.Close()
		defer s.Close()
		testBasicIO(t, src, conn)
	})

	t.Run("conn -> server", func(t *testing.T) {
		nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
			s, err := NewServer(config.Quic_builder{
				Host: proto.String("127.0.0.1:0"),
				Tls: node.TlsServerConfig_builder{
					Certificates: []*node.Certificate{
						node.Certificate_builder{
							Cert: cert,
							Key:  key,
						}.Build(),
					},
				}.Build(),
			}.Build())
			assert.NoError(t, err)

			server := make(chan net.Conn)

			go func() {
				for {
					conn, err := s.Accept()
					if err != nil {
						break
					}

					server <- conn
				}
			}()

			qc, err := NewClient(node.Quic_builder{
				Host: proto.String(s.Addr().String()),
				Tls: node.TlsConfig_builder{
					Enable:             proto.Bool(true),
					InsecureSkipVerify: proto.Bool(true),
				}.Build(),
			}.Build(), nil)
			assert.NoError(t, err)

			conn, err := qc.Conn(context.TODO(), netapi.EmptyAddr)
			assert.NoError(t, err)

			// fmt.Println("conn", conn.RemoteAddr())

			n, err := conn.Write([]byte("hello"))
			assert.NoError(t, err)

			src := <-server

			_, err = src.Read(make([]byte, n))
			assert.NoError(t, err)

			// fmt.Println("src", src.RemoteAddr(), conn.RemoteAddr())

			return conn, src, func() {
				conn.Close()
				src.Close()
				s.Close()
			}, nil
		})
	})
}

func TestQuic(t *testing.T) {
	s, err := NewServer(config.Quic_builder{
		Host: proto.String("127.0.0.1:0"),
		Tls: node.TlsServerConfig_builder{
			Certificates: []*node.Certificate{
				node.Certificate_builder{Cert: cert, Key: key}.Build(),
			},
		}.Build(),
	}.Build())
	assert.NoError(t, err)

	defer s.Close()

	size := 20000

	spc, err := s.Packet(context.TODO())
	assert.NoError(t, err)

	go func() {
		for {
			buf := make([]byte, size)
			n, addr, err := spc.ReadFrom(buf)
			if err != nil {
				break
			}

			id := binary.BigEndian.Uint64(buf[:8])
			t.Log("packet read", n, id)

			n, err = spc.WriteTo(buf[:n], addr)
			assert.NoError(t, err)

			t.Log("write back", n, id)
		}
	}()

	qc, err := NewClient(node.Quic_builder{
		Host: proto.String(s.Addr().String()),
		Tls: node.TlsConfig_builder{
			Enable:             proto.Bool(true),
			InsecureSkipVerify: proto.Bool(true),
		}.Build(),
	}.Build(), nil)
	assert.NoError(t, err)

	// qc.(*Client).qlogWriter = func() (io.WriteCloser, error) {
	// 	path, err := filepath.Abs(".")
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	f, err := os.CreateTemp(path, "*.qlog")
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	t.Log("new qlog", f.Name())

	// 	return f, nil
	// }

	pc, err := qc.PacketConn(context.TODO(), netapi.EmptyAddr)
	assert.NoError(t, err)

	var idBytesMap syncmap.SyncMap[uint64, []byte]

	var wg sync.WaitGroup

	go func() {
		for {
			buf := make([]byte, size)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				break
			}

			rid := binary.BigEndian.Uint64(buf[:n])

			t.Log("packet read back", n, addr, rid)

			data, ok := idBytesMap.Load(rid)
			if !ok {
				t.Error("not found", rid, n)
				t.Fail()
			}

			if !bytes.Equal(data, buf[:n]) {
				t.Error("not equal", len(data), n, data[:8], buf[:8], rid)
				t.Fail()
			}

			wg.Done()
		}
	}()

	for id := range 10 {
		wg.Add(1)
		length := mrand.IntN(size)
		data := make([]byte, length)

		_, err := io.ReadFull(rand.Reader, data)
		assert.NoError(t, err)

		idb := binary.BigEndian.AppendUint64(nil, uint64(id))

		data = append(idb, data...)

		idBytesMap.Store(uint64(id), data)

		// sleep to send slow, otherwise the udp packet will be dropped
		time.Sleep(time.Millisecond * 30)

		_, err = pc.WriteTo(data, nil)
		assert.NoError(t, err)
	}

	time.Sleep(time.Second)

	for _, v := range s.(*Server).natMap.Range {
		for k, v := range v.frag.mergeMap.Range {
			t.Log("server remain", k, "total", v.Total, "current", v.Count, "total len", v.TotalLen)
		}
	}

	for _, v := range qc.(*Client).natMap.Range {
		for k, v := range v.session.frag.mergeMap.Range {
			t.Log("client remain", k, "total", v.Total, "current", v.Count, "total len", v.TotalLen)
		}
	}

	wg.Wait()
}

// testBasicIO tests that the data sent on c1 is properly received on c2.
func testBasicIO(t *testing.T, c1, c2 net.Conn) {
	want := make([]byte, 1<<20)
	mrandv1.New(mrandv1.NewSource(0)).Read(want)

	dataCh := make(chan []byte)
	go func() {
		rd := bytes.NewReader(want)
		if err := chunkedCopy(c1, rd); err != nil {
			t.Errorf("unexpected c1.Write error: %v", err)
		}
		if err := c1.Close(); err != nil {
			t.Errorf("unexpected c1.Close error: %v", err)
		}
	}()

	go func() {
		wr := new(bytes.Buffer)
		if err := chunkedCopy(wr, c2); err != nil {
			t.Errorf("unexpected c2.Read error: %v", err)
		}
		if err := c2.Close(); err != nil {
			t.Errorf("unexpected c2.Close error: %v", err)
		}
		dataCh <- wr.Bytes()
	}()

	if got := <-dataCh; !bytes.Equal(got, want) {
		t.Error("transmitted data differs", len(got), len(want))
	}
}

// chunkedCopy copies from r to w in fixed-width chunks to avoid
// causing a Write that exceeds the maximum packet size for packet-based
// connections like "unixpacket".
// We assume that the maximum packet size is at least 1024.
func chunkedCopy(w io.Writer, r io.Reader) error {
	b := make([]byte, 1024)
	_, err := io.CopyBuffer(struct{ io.Writer }{w}, struct{ io.Reader }{r}, b)
	return err
}

func TestAddr(t *testing.T) {
	qaddr := &QuicAddr{
		ID:   quic.StreamID(1),
		Addr: netapi.EmptyAddr,
		time: 1000,
	}

	addr, err := netapi.ParseAddress("udp", qaddr.String())
	assert.NoError(t, err)

	assert.Equal(t, addr.String(), qaddr.String())
	t.Log(qaddr, addr)
}
