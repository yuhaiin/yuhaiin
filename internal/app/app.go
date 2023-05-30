package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	web "github.com/Asutorufa/yuhaiin/internal/http"
	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/components/config"
	"github.com/Asutorufa/yuhaiin/pkg/components/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/components/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/components/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"go.etcd.io/bbolt"
	"google.golang.org/grpc"
)

var (
	Mux = http.NewServeMux()

	so           *StartOpt
	HttpListener net.Listener
	Node         *node.Nodes
	closers      []io.Closer
)

type StartOpt struct {
	ConfigPath string
	Host       string
	Setting    config.Setting

	ProcessDumper listener.ProcessDumper
	GRPCServer    *grpc.Server
}

func AddComponent[T any](t T) T {
	if z, ok := any(t).(config.Observer); ok {
		so.Setting.AddObserver(z)
	}

	if z, ok := any(t).(io.Closer); ok {
		closers = append(closers, z)
	}

	return t
}

func AddCloser(z io.Closer) {
	closers = append(closers, z)
}

func Close() error {
	for _, z := range closers {
		z.Close()
	}
	log.Close()
	sysproxy.Unset()

	Mux = http.NewServeMux()
	so = nil
	HttpListener = nil
	Node = nil
	closers = nil
	return nil
}

func initBboltDB(path string) (*bbolt.DB, error) {
	db, err := bbolt.Open(path, os.ModePerm, &bbolt.Options{Timeout: time.Second * 2})
	switch err {
	case bbolt.ErrInvalid, bbolt.ErrChecksum, bbolt.ErrVersionMismatch:
		if err = os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove invalid cache file failed: %w", err)
		}
		log.Info("remove invalid cache file and create new one")
		return bbolt.Open(path, os.ModePerm, &bbolt.Options{Timeout: time.Second})
	}

	return db, err
}

func Start(opt StartOpt) error {
	so = &opt

	db, err := initBboltDB(PathGenerator.Cache(so.ConfigPath))
	if err != nil {
		return fmt.Errorf("init bbolt cache failed: %w", err)
	}
	AddCloser(db)

	HttpListener, err = net.Listen("tcp", so.Host)
	if err != nil {
		return err
	}

	fmt.Println(version.Art)
	log.Info("config", "path", so.ConfigPath, "grpc&http host", so.Host)

	so.Setting.AddObserver(config.ObserverFunc(sysproxy.Update))
	so.Setting.AddObserver(config.ObserverFunc(func(s *pc.Setting) { log.Set(s.GetLogcat(), PathGenerator.Log(so.ConfigPath)) }))
	so.Setting.AddObserver(config.ObserverFunc(func(s *pc.Setting) { dialer.DefaultInterfaceName = s.GetNetInterface() }))

	filestore := node.NewFileStore(PathGenerator.Node(so.ConfigPath))
	// proxy access point/endpoint
	Node = node.NewNodes(filestore)
	subscribe := node.NewSubscribe(filestore)
	tag := node.NewTag(filestore)

	// make dns flow across all proxy chain
	appDialer := &storeProxy{}

	// local,remote,bootstrap dns
	_ = AddComponent(resolver.NewBootstrap(appDialer))
	local := AddComponent(resolver.NewLocal(appDialer))
	remote := AddComponent(resolver.NewRemote(appDialer))
	// bypass dialer and dns request
	st := AddComponent(shunt.NewShunt(NewShuntOpt(local, remote)))
	// connections' statistic & flow data
	stcs := AddComponent(statistics.NewConnStore(cache.NewCache(db, "flow_data"), st, so.ProcessDumper))
	hosts := AddComponent(resolver.NewHosts(stcs, st))
	// wrap dialer and dns resolver to fake ip, if use
	fakedns := AddComponent(resolver.NewFakeDNS(hosts, hosts, cache.NewCache(db, "fakedns_cache")))
	// dns server/tun dns hijacking handler
	dnsServer := AddComponent(resolver.NewDNSServer(fakedns))
	// give dns a dialer
	appDialer.Proxy = fakedns
	ss := AddComponent(inbound.NewHandler(fakedns))
	// inbound server
	_ = AddComponent(inbound.NewListener(dnsServer, ss))
	// http page
	web.Httpserver(NewHttpOption(subscribe, stcs, tag, st))
	// grpc server
	RegisterGrpcService(subscribe, stcs, tag)

	return nil
}

func RegisterGrpcService(sub gn.SubscribeServer, conns gs.ConnectionsServer, tag gn.TagServer) {
	if so.GRPCServer == nil {
		return
	}

	so.GRPCServer.RegisterService(&gc.ConfigService_ServiceDesc, so.Setting)
	so.GRPCServer.RegisterService(&gn.Node_ServiceDesc, Node)
	so.GRPCServer.RegisterService(&gn.Subscribe_ServiceDesc, sub)
	so.GRPCServer.RegisterService(&gs.Connections_ServiceDesc, conns)
	so.GRPCServer.RegisterService(&gn.Tag_ServiceDesc, tag)
}

func NewShuntOpt(local, remote proxy.Resolver) shunt.Opts {
	return shunt.Opts{
		DirectDialer:   direct.Default,
		DirectResolver: local,
		ProxyDialer:    Node,
		ProxyResolver:  remote,
		BlockDialer:    reject.Default,
		BLockResolver:  proxy.ErrorResolver(func(domain string) error { return proxy.NewBlockError(-2, domain) }),
		DefaultMode:    bypass.Mode_proxy,
	}
}

func NewHttpOption(sub gn.SubscribeServer, conns gs.ConnectionsServer, tag gn.TagServer, st *shunt.Shunt) web.HttpServerOption {
	return web.HttpServerOption{
		Mux:         Mux,
		NodeServer:  Node,
		Subscribe:   sub,
		Connections: conns,
		Config:      so.Setting,
		Tag:         tag,
		Shunt:       st,
	}
}

var PathGenerator = pathGenerator{}

type pathGenerator struct{}

func (p pathGenerator) Lock(dir string) string   { return p.makeDir(filepath.Join(dir, "LOCK")) }
func (p pathGenerator) Node(dir string) string   { return p.makeDir(filepath.Join(dir, "node.json")) }
func (p pathGenerator) Config(dir string) string { return p.makeDir(filepath.Join(dir, "config.json")) }
func (p pathGenerator) Log(dir string) string {
	return p.makeDir(filepath.Join(dir, "log", "yuhaiin.log"))
}
func (pathGenerator) makeDir(s string) string {
	if _, err := os.Stat(s); errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(filepath.Dir(s), os.ModePerm)
	}

	return s
}
func (p pathGenerator) Cache(dir string) string { return p.makeDir(filepath.Join(dir, "cache")) }

type storeProxy struct{ proxy.Proxy }

func (w *storeProxy) Conn(ctx context.Context, addr proxy.Address) (net.Conn, error) {
	return w.Proxy.Conn(proxy.NewStore(ctx), addr)
}

func (w *storeProxy) PacketConn(ctx context.Context, addr proxy.Address) (net.PacketConn, error) {
	return w.Proxy.PacketConn(proxy.NewStore(ctx), addr)
}

func (w *storeProxy) Dispatch(ctx context.Context, addr proxy.Address) (proxy.Address, error) {
	return w.Proxy.Dispatch(proxy.NewStore(ctx), addr)
}
