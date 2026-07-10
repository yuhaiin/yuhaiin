package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func main() {
	_ = fixed.Config{}
	_ = socks5.Config{}

	pro, err := register.ContractDialer(contractnode.Node{
		ID:     "example",
		Name:   "example",
		Origin: "example",
		Chain: []contractnode.Protocol{
			protocol(contractnode.Simple{
				Host: "127.0.0.1",
				Port: 1080,
			}),
			protocol(contractnode.Socks5{}),
		},
	})
	if err != nil {
		panic(err)
	}

	c := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				add, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %w", err)
				}
				return pro.Conn(ctx, add)
			}},
	}
	resp, err := c.Get("https://www.google.com")
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	defer resp.Body.Close()
	log.Println(buf.String())
}

func protocol[T contractnode.ProtocolPayload](value T) contractnode.Protocol {
	protocol, err := contractnode.NewTypedProtocol(value)
	if err != nil {
		panic(err)
	}
	return protocol
}
