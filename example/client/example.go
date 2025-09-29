package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"google.golang.org/protobuf/proto"
)

func main() {
	node := point.Point_builder{
		Protocols: []*protocol.Protocol{
			protocol.Protocol_builder{
				NetworkSplit: protocol.NetworkSplit_builder{
					Tcp: protocol.Protocol_builder{
						Simple: protocol.Simple_builder{
							Host: proto.String("127.0.0.1"),
							Port: proto.Int32(1080),
						}.Build(),
					}.Build(),
					Udp: protocol.Protocol_builder{
						Direct: &protocol.Direct{},
					}.Build(),
				}.Build(),
			}.Build(),
			protocol.Protocol_builder{
				Socks5: &protocol.Socks5{},
			}.Build(),
		},
	}

	pro, err := register.Dialer(node.Build())
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
