package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"google.golang.org/protobuf/proto"
)

var cert = `-----BEGIN CERTIFICATE-----
MIIBeTCCASugAwIBAgIQGnXgwvDnen8u0IkKfofRdjAFBgMrZXAwUDELMAkGA1UE
BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExJjAkBgNVBAMTHUdsb2Jh
bFNpZ24gRUNDIE9WIFNTTCBDQSAyMDE4MB4XDTI1MDQwNzA3MDEwMloXDTM1MDQw
NTA3MDEwMlowFTETMBEGA1UEAxMKd3d3Lnh4LmNvbTAqMAUGAytlcAMhAEOKIvfs
bmOK2mGPyoZkfo/9aNSFBmq6pHdVNQ9lgJqZo1YwVDAOBgNVHQ8BAf8EBAMCBaAw
HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwFQYD
VR0RBA4wDIIKd3d3Lnh4LmNvbTAFBgMrZXADQQDu9Zv5Z6sou4oQ3Y7v9i9fibjA
ZJO5mhLKx5vJI2pB/i7taNnnACb+CNZfOuBVbgHsDPJnCNgpa6XBOgj4eBEE
-----END CERTIFICATE-----
`

var key = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILArmTMFo0d2X9cTPVlgKGVO+wyqkQFjPlNnN5wmTq6G
-----END PRIVATE KEY-----
`

func main() {
	r, err := resolver.New(resolver.Config{
		Type: dns.Type_udp,
		Host: "8.8.8.8",
	})
	if err != nil {
		panic(err)
	}

	dialer.SetBootstrap(r)

	node := point.Point_builder{
		Protocols: []*protocol.Protocol{
			protocol.Protocol_builder{
				Simple: protocol.Simple_builder{
					Host: proto.String("ip.sb"),
					Port: proto.Int32(443),
				}.Build(),
			}.Build(),
			protocol.Protocol_builder{
				Tls: protocol.TlsConfig_builder{
					Enable:             proto.Bool(true),
					InsecureSkipVerify: proto.Bool(true),
					ServerNames:        []string{"ip.sb"},
				}.Build(),
			}.Build(),

			protocol.Protocol_builder{
				TlsTermination: protocol.TlsTermination_builder{
					Tls: protocol.TlsServerConfig_builder{
						Certificates: []*protocol.Certificate{
							protocol.Certificate_builder{
								Cert: []byte(cert),
								Key:  []byte(key),
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
		},
	}

	pro, err := register.Dialer(node.Build())
	if err != nil {
		panic(err)
	}

	c := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				add, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %w", err)
				}
				conn, err := pro.Conn(ctx, add)
				if err != nil {
					return nil, err
				}

				return conn, nil
			}},
	}

	resp, err := c.Get("https://ip.sb")
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	defer resp.Body.Close()
	log.Println(buf.String())
}
