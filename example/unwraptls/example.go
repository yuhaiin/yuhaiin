package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/register"
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
		Type: "udp",
		Host: "8.8.8.8",
	})
	if err != nil {
		panic(err)
	}

	netapi.SetBootstrap(r)

	pro, err := register.ContractDialer(contractnode.Node{
		ID:     "unwrap-tls-example",
		Name:   "unwrap-tls-example",
		Origin: "example",
		Chain: []contractnode.Protocol{
			protocol("simple", contractnode.Object{
				"host": "ip.sb",
				"port": int32(443),
			}),
			protocol("tls", contractnode.Object{
				"enable":               true,
				"insecure_skip_verify": true,
				"servernames":          []string{"ip.sb"},
			}),
			protocol("tls_termination", contractnode.Object{
				"tls": map[string]any{
					"certificates": []map[string]any{{
						"cert": []byte(cert),
						"key":  []byte(key),
					}},
				},
			}),
		},
	})
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

func protocol(typ string, value contractnode.Object) contractnode.Protocol {
	protocol, err := contractnode.NewProtocol(typ, value)
	if err != nil {
		panic(err)
	}
	return protocol
}
