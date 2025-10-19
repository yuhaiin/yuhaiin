package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/reverse"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
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
		Type: config.Type_udp,
		Host: "8.8.8.8",
	})
	if err != nil {
		panic(err)
	}

	netapi.SetBootstrap(r)

	node := node.Point_builder{
		Protocols: []*node.Protocol{
			node.Protocol_builder{
				Direct: node.Direct_builder{}.Build(),
			}.Build(),

			node.Protocol_builder{
				Tls: node.TlsConfig_builder{
					Enable:             proto.Bool(true),
					InsecureSkipVerify: proto.Bool(true),
					ServerNames:        []string{"www.youtube.com"},
				}.Build(),
			}.Build(),

			node.Protocol_builder{
				HttpTermination: node.HttpTermination_builder{
					Headers: map[string]*node.HttpTerminationHttpHeaders{
						"*.youtube.com": node.HttpTerminationHttpHeaders_builder{
							Headers: []*node.HttpHeader{
								node.HttpHeader_builder{
									Key:   proto.String("User-Agent"),
									Value: proto.String("curl/8.13.0"),
								}.Build(),
								node.HttpHeader_builder{
									Key:   proto.String("Accept"),
									Value: proto.String("*/*"),
								}.Build(),
							},
						}.Build(),
					},
				}.Build(),
			}.Build(),

			node.Protocol_builder{
				TlsTermination: node.TlsTermination_builder{
					Tls: node.TlsServerConfig_builder{
						Certificates: []*node.Certificate{
							node.Certificate_builder{
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

	resp, err := c.Get("https://www.youtube.com")
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	io.CopyN(os.Stdout, resp.Body, 1024)
}
