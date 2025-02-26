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
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	pcl "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
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
		Cache:          cache.NewMemoryCache(),
	})
	if err != nil {
		panic(err)
	}
	defer instance.Close()

	point, err := instance.Node.Save(context.TODO(), point.Point_builder{
		Group: proto.String("test"),
		Name:  proto.String("test"),
		Protocols: []*protocol.Protocol{
			protocol.Protocol_builder{
				Simple: protocol.Simple_builder{
					Host: proto.String("127.0.0.1"),
					Port: proto.Int32(1080),
				}.Build(),
			}.Build(),
			protocol.Protocol_builder{
				Socks5: &protocol.Socks5{},
			}.Build(),
		},
	}.Build())
	if err != nil {
		panic(err)
	}

	_, err = instance.Node.Use(context.TODO(), gn.UseReq_builder{
		Tcp:  proto.Bool(true),
		Udp:  proto.Bool(true),
		Hash: proto.String(point.GetHash()),
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
				return configuration.ProxyChain.Conn(ctx, add)
			}},
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

	config.SetServer(&listener.InboundConfig{})
	config.SetSystemProxy(&pc.SystemProxy{})
	config.GetDns().SetServer("")
	config.GetLogcat().SetLevel(pcl.LogLevel_error)

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
