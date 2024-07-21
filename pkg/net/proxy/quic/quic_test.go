package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	mrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
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

func TestQuic(t *testing.T) {
	s, err := NewServer(&listener.Inbound_Quic{
		Quic: &listener.Quic{
			Host: "127.0.0.1:1090",
			Tls: &listener.TlsConfig{
				Certificates: []*listener.Certificate{
					{
						Cert: cert,
						Key:  key,
					},
				},
			},
		},
	})
	assert.NoError(t, err)

	defer s.Close()

	go func() {
		spc, err := s.Packet(context.TODO())
		assert.NoError(t, err)

		for {
			buf := make([]byte, 65536)
			n, addr, err := spc.ReadFrom(buf)
			if err != nil {
				break
			}

			// go func() {
			_, err = spc.WriteTo(buf[:n], addr)
			assert.NoError(t, err)
			// }()
		}
	}()

	qc, err := NewClient(&protocol.Protocol_Quic{
		Quic: &protocol.Quic{
			Host: "127.0.0.1:1090",
			Tls: &protocol.TlsConfig{
				Enable:             true,
				InsecureSkipVerify: true,
			},
		},
	})(nil)
	assert.NoError(t, err)

	pc, err := qc.PacketConn(context.TODO(), netapi.EmptyAddr)
	assert.NoError(t, err)

	var wg sync.WaitGroup
	id := atomic.Uint64{}
	var idBytesMap syncmap.SyncMap[uint64, []byte]
	for range 10 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			length := mrand.IntN(nat.MaxSegmentSize - 1024)
			data := make([]byte, length)
			recevie := make([]byte, nat.MaxSegmentSize)

			_, err := io.ReadFull(rand.Reader, data)
			assert.NoError(t, err)

			id := id.Add(1)

			// defer fmt.Println(id)

			idb := binary.BigEndian.AppendUint64(nil, uint64(id))

			data = append(idb, data...)

			idBytesMap.Store(uint64(id), data)

			_, err = pc.WriteTo(data, nil)
			assert.NoError(t, err)

			n, _, err := pc.ReadFrom(recevie)
			assert.NoError(t, err)

			rid := binary.BigEndian.Uint64(recevie[:n])

			data, ok := idBytesMap.Load(rid)
			if !ok {
				t.Error("not found")
				t.Fail()
			}

			if !bytes.Equal(data, recevie[:n]) {
				t.Error("not equal", len(data), n, data[:8], recevie[:8], rid)
				t.Fail()
			}
		}()
	}

	wg.Wait()
}

func TestSimple(t *testing.T) {
	s, err := simple.NewServer(&listener.Inbound_Tcpudp{
		Tcpudp: &listener.Tcpudp{
			Host:    "127.0.0.1:1090",
			Control: listener.TcpUdpControl_tcp_udp_control_all,
		},
	})
	assert.NoError(t, err)

	defer s.Close()

	go func() {
		spc, err := s.Packet(context.TODO())
		assert.NoError(t, err)

		for range system.Procs {
			go func() {
				for {
					buf := make([]byte, 65536)
					n, addr, err := spc.ReadFrom(buf)
					if err != nil {
						break
					}

					// go func() {
					_, err = spc.WriteTo(buf[:n], addr)
					assert.NoError(t, err)
					// }()
				}
			}()
		}
	}()

	qc, err := simple.NewClient(&protocol.Protocol_Simple{
		Simple: &protocol.Simple{
			Host: "127.0.0.1",
			Port: 1090,
		},
	})(nil)
	assert.NoError(t, err)

	pc, err := qc.PacketConn(context.TODO(), netapi.EmptyAddr)
	assert.NoError(t, err)

	id := atomic.Uint64{}
	var idBytesMap syncmap.SyncMap[uint64, []byte]

	go func() {

		for {
			recevie := make([]byte, nat.MaxSegmentSize)
			n, _, err := pc.ReadFrom(recevie)
			assert.NoError(t, err)

			rid := binary.BigEndian.Uint64(recevie[:n])

			data, ok := idBytesMap.LoadAndDelete(rid)
			if !ok {
				t.Error("not found")
				t.Fail()
			}

			if !bytes.Equal(data, recevie[:n]) {
				t.Error("not equal", len(data), n, data[:8], recevie[:8], rid)
				t.Fail()
			}
		}
	}()
	for range 10 {
		go func() {
			length := mrand.IntN(1024)
			data := make([]byte, length)

			_, err := io.ReadFull(rand.Reader, data)
			assert.NoError(t, err)

			id := id.Add(1)

			idb := binary.BigEndian.AppendUint64(nil, uint64(id))

			data = append(idb, data...)

			idBytesMap.Store(uint64(id), data)

			_, err = pc.WriteTo(data, nil)
			assert.NoError(t, err)

		}()
	}

	time.Sleep(time.Second * 10)

	idBytesMap.Range(func(key uint64, value []byte) bool {
		t.Log(key, len(value))
		return true
	})
}
