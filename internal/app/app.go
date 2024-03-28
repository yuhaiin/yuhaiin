package app

import (
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
	"github.com/Asutorufa/yuhaiin/pkg/components/tools"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	gt "github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"go.etcd.io/bbolt"
	"google.golang.org/grpc"

	_ "github.com/Asutorufa/yuhaiin/pkg/net/mux"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/drop"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/grpc"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/reality"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks4a"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/trojan"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vless"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
)

var App = app{Mux: http.NewServeMux()}

type app struct {
	Mux          *http.ServeMux
	so           *StartOpt
	HttpListener net.Listener
	Node         *node.Nodes
	Tools        *tools.Tools
	DB           *bbolt.DB
	closers      []io.Closer
}

type StartOpt struct {
	ConfigPath string
	Host       string
	Setting    config.Setting

	ProcessDumper listener.ProcessDumper
	GRPCServer    *grpc.Server
}

func AddComponent[T any](name string, t T) T {
	if z, ok := any(t).(config.Observer); ok {
		App.so.Setting.AddObserver(z)
	}

	if z, ok := any(t).(io.Closer); ok {
		AddCloser(name, z)
	}

	return t
}

func AddCloser(name string, z io.Closer) {
	App.closers = append(App.closers, &moduleCloser{z, name})
}

type moduleCloser struct {
	io.Closer
	name string
}

func (m *moduleCloser) Close() error {
	log.Info("close", "module", m.name)
	defer log.Info("closed", "module", m.name)
	return m.Closer.Close()
}
func Close() error {
	for _, v := range App.closers {
		v.Close()
	}

	log.Close()

	sysproxy.Unset()

	App = app{Mux: http.NewServeMux()}

	return nil
}

func OpenBboltDB(path string) (*bbolt.DB, error) {
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

func Start(opt StartOpt) (err error) {
	App.so = &opt

	if App.DB == nil {
		App.DB, err = OpenBboltDB(PathGenerator.Cache(App.so.ConfigPath))
		if err != nil {
			return fmt.Errorf("init bbolt cache failed: %w", err)
		}
		AddCloser("bbolt_db", App.DB)
	}

	App.HttpListener, err = net.Listen("tcp", App.so.Host)
	if err != nil {
		return err
	}
	AddCloser("http_listener", App.HttpListener)

	App.so.Setting.AddObserver(config.ObserverFunc(func(s *pc.Setting) { log.Set(s.GetLogcat(), PathGenerator.Log(App.so.ConfigPath)) }))

	fmt.Println(version.Art)
	log.Info("config", "path", App.so.ConfigPath, "grpc&http host", App.so.Host)

	App.so.Setting.AddObserver(config.ObserverFunc(sysproxy.Update()))
	App.so.Setting.AddObserver(config.ObserverFunc(func(s *pc.Setting) { dialer.DefaultInterfaceName = s.GetNetInterface() }))

	// proxy access point/endpoint
	App.Node = node.NewNodes(PathGenerator.Node(App.so.ConfigPath))
	subscribe := App.Node.Subscribe()
	tag := App.Node.Tag()

	// make dns flow across all proxy chain
	dynamicProxy := netapi.NewDynamicProxy(direct.Default)

	// local,remote,bootstrap dns
	dns := AddComponent("resolver", resolver.NewResolver(dynamicProxy))
	// bypass dialer and dns request
	st := AddComponent("shunt", shunt.NewShunt(App.Node.Outbound(), dns, opt.ProcessDumper))
	App.Node.SetRuleTags(st.Tags)
	// connections' statistic & flow data
	stcs := AddComponent("statistic", statistics.NewConnStore(cache.NewCache(App.DB, "flow_data"), st))
	hosts := AddComponent("hosts", resolver.NewHosts(stcs, st))
	// wrap dialer and dns resolver to fake ip, if use
	fakedns := AddComponent("fakedns", resolver.NewFakeDNS(hosts, hosts, cache.NewCache(App.DB, "fakedns_cache"), cache.NewCache(App.DB, "fakedns_cachev6")))
	// dns server/tun dns hijacking handler
	dnsServer := AddComponent("dnsServer", resolver.NewDNSServer(fakedns))
	// make dns flow across all proxy chain
	dynamicProxy.Set(fakedns)
	// inbound server
	_ = AddComponent("inbound_listener",
		inbound.NewListener(dnsServer, fakedns))
	// tools
	App.Tools = tools.NewTools(fakedns, opt.Setting, st.Update)
	// http page
	web.Httpserver(NewHttpOption(subscribe, stcs, tag, st))
	// grpc server
	RegisterGrpcService(subscribe, stcs, tag)

	return nil
}

func RegisterGrpcService(sub gn.SubscribeServer, conns gs.ConnectionsServer, tag gn.TagServer) {
	if App.so.GRPCServer == nil {
		return
	}

	App.so.GRPCServer.RegisterService(&gc.ConfigService_ServiceDesc, App.so.Setting)
	App.so.GRPCServer.RegisterService(&gn.Node_ServiceDesc, App.Node)
	App.so.GRPCServer.RegisterService(&gn.Subscribe_ServiceDesc, sub)
	App.so.GRPCServer.RegisterService(&gs.Connections_ServiceDesc, conns)
	App.so.GRPCServer.RegisterService(&gn.Tag_ServiceDesc, tag)
	App.so.GRPCServer.RegisterService(&gt.Tools_ServiceDesc, App.Tools)
}

func NewHttpOption(sub gn.SubscribeServer, conns gs.ConnectionsServer, tag gn.TagServer, st *shunt.Shunt) web.HttpServerOption {
	return web.HttpServerOption{
		Mux:         App.Mux,
		NodeServer:  App.Node,
		Subscribe:   sub,
		Connections: conns,
		Config:      App.so.Setting,
		Tag:         tag,
		Shunt:       st,
		Tools:       App.Tools,
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
		_ = os.MkdirAll(filepath.Dir(s), os.ModePerm)
	}

	return s
}
func (p pathGenerator) Cache(dir string) string { return p.makeDir(filepath.Join(dir, "cache")) }
