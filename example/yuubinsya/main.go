package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"google.golang.org/protobuf/proto"

	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
)

type r struct {
	netapi.Resolver
}

func (r *r) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	return r.Resolver.LookupIP(ctx, domain, func(li *netapi.LookupIPOption) {
		li.Mode = netapi.ResolverModePreferIPv4
	})
}

func main() {
	netapi.SetBootstrap(&r{resolver.Internet})
	interfaces.SetDefaultInterfaceName("")
	configuration.IPv6.Store(false)

	handler := inbound.NewInbound(direct.Default)

	password := os.Getenv("PASSWORD")
	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0:50051"
	}

	fmt.Println("password:", password, "host:", host)

	cfg := config.Inbound_builder{
		Enabled: proto.Bool(true),
		Tcpudp: config.Tcpudp_builder{
			Host:    proto.String(host),
			Control: config.TcpUdpControl_tcp_udp_control_all.Enum(),
		}.Build(),
		Transport: []*config.Transport{
			config.Transport_builder{
				Websocket: config.Websocket_builder{}.Build(),
			}.Build(),
			config.Transport_builder{
				Http2: config.Http2_builder{}.Build(),
			}.Build(),
		},
		Yuubinsya: config.Yuubinsya_builder{
			Password:    proto.String(password),
			UdpCoalesce: proto.Bool(false),
		}.Build(),
	}.Build()
	lis, err := register.Listen(cfg, handler)
	if err != nil {
		panic(err)
	}
	defer lis.Close()

	ctx, ncancel := signal.NotifyContext(context.TODO(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer ncancel()

	<-ctx.Done()
}
