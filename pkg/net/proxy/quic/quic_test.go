package quic

import (
	"bytes"
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
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
		Quic: &listener.Quic2{
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

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer cancel()

		spc, err := s.Packet(ctx)
		assert.NoError(t, err)

		buf := make([]byte, 65536)

		for range 2 {
			n, addr, err := spc.ReadFrom(buf)
			assert.NoError(t, err)

			t.Log(string(buf[:n]), addr, bytes.Equal(buf[:n], append(cert, cert...)))
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

	_, err = pc.WriteTo(append(cert, cert...), nil)
	assert.NoError(t, err)

	_, err = pc.WriteTo(append(cert, cert...), nil)
	assert.NoError(t, err)

	<-ctx.Done()
}
