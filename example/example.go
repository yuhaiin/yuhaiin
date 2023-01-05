package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/node/register"
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

	pro, err := register.Dialer(node)
	if err != nil {
		panic(err)
	}

	c := http.Client{
		Transport: &http.Transport{Dial: func(network, addr string) (net.Conn, error) {
			add, err := proxy.ParseAddress(proxy.PaseNetwork(network), addr)
			if err != nil {
				return nil, fmt.Errorf("parse address failed: %w", err)
			}
			return pro.Conn(add)
		}},
	}
	resp, err := c.Get("https://www.google.com")
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	defer resp.Body.Close()
	log.Println(buf.String())
}
