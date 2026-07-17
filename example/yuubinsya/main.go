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
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2/v2"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
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

	lis, err := fixed.NewServer(fixed.ServerConfig{
		Host:    host,
		Control: fixed.ControlAll,
	})
	if err != nil {
		panic(err)
	}
	lis, err = websocket.NewServer(websocket.ServerConfig{}, lis)
	if err != nil {
		panic(err)
	}
	lis, err = http2.NewServer(http2.ServerConfig{}, lis)
	if err != nil {
		panic(err)
	}
	server, err := yuubinsya.NewServer(yuubinsya.ServerConfig{
		Password: password,
	}, lis, handler)
	if err != nil {
		panic(err)
	}
	defer server.Close()

	ctx, ncancel := signal.NotifyContext(context.TODO(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer ncancel()

	<-ctx.Done()
}
