package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/app"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/proto"
)

func main() {
	instance, err := app.Start(&app.StartOptions{
		ConfigPath:     "/tmp/test",
		Auth:           nil,
		GRPCServer:     nil,
		ProcessDumper:  nil,
		BypassConfig:   &mockDB{},
		ResolverConfig: &mockDB{},
		InboundConfig:  &mockDB{},
		ChoreConfig:    &mockDB{},
	})
	if err != nil {
		panic(err)
	}
	defer instance.Close()

	pp, err := instance.Node.Save(context.TODO(), node.Point_builder{
		Group: proto.String("test"),
		Name:  proto.String("test"),
		Protocols: []*node.Protocol{
			node.Protocol_builder{
				NetworkSplit: node.NetworkSplit_builder{
					Tcp: node.Protocol_builder{
						Simple: node.Simple_builder{
							Host: proto.String("127.0.0.1"),
							Port: proto.Int32(1080),
						}.Build(),
					}.Build(),
					Udp: node.Protocol_builder{
						Direct: &node.Direct{},
					}.Build(),
				}.Build(),
			}.Build(),
			node.Protocol_builder{
				Socks5: &node.Socks5{},
			}.Build(),
		},
	}.Build())
	if err != nil {
		panic(err)
	}

	_, err = instance.Node.Use(context.TODO(), api.UseReq_builder{
		Hash: proto.String(pp.GetHash()),
	}.Build())
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

				ctx = netapi.WithContext(ctx)

				return configuration.ProxyChain.Conn(ctx, add)
			},
		},
	}

	req, err := http.NewRequest("GET", "http://ip.sb", nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("User-Agent", "curl/8.12.1")

	resp, err := c.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	err = resp.Write(os.Stdout)
	if err != nil {
		log.Fatal(err)
	}
}

type mockDB struct{}

func (m *mockDB) Batch(f ...func(*pc.Setting) error) error {
	return m.View(f...)
}

func (m *mockDB) View(f ...func(*pc.Setting) error) error {
	config := pc.DefaultSetting("/tmp/test")

	config.SetServer(&pc.InboundConfig{})
	config.SetSystemProxy(&pc.SystemProxy{})
	config.GetDns().SetServer("")
	config.GetLogcat().SetLevel(pc.LogLevel_error)

	for i := range f {
		if err := f[i](config); err != nil {
			return err
		}
	}

	return nil
}

func (m *mockDB) Dir() string {
	return "/tmp/test"
}
