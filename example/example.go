package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

func main() {
	node := &point.Point{
		Protocols: []*protocol.Protocol{
			{
				Protocol: &protocol.Protocol_Simple{
					Simple: &protocol.Simple{
						Host:             "127.0.0.1",
						Port:             1080,
						PacketConnDirect: true,
					},
				},
			},
			{
				Protocol: &protocol.Protocol_Socks5{
					Socks5: &protocol.Socks5{},
				},
			},
		},
	}

	pro, err := point.Dialer(node)
	if err != nil {
		panic(err)
	}

	c := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				add, err := netapi.ParseAddress(netapi.PaseNetwork(network), addr)
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
