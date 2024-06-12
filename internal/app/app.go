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

	"github.com/Asutorufa/yuhaiin/internal/appapi"
	web "github.com/Asutorufa/yuhaiin/internal/http"
	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/components/config"
	"github.com/Asutorufa/yuhaiin/pkg/components/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/components/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/components/route"
	"github.com/Asutorufa/yuhaiin/pkg/components/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/components/tools"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"go.etcd.io/bbolt"

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

func AddComponent[T any](a *appapi.Start, name string, t T) T {
	if z, ok := any(t).(config.Observer); ok {
		a.Setting.AddObserver(z)
	}

	if z, ok := any(t).(io.Closer); ok {
		a.AddCloser(name, z)
	}

	return t
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

func Start(opt appapi.Start) (_ *appapi.Components, err error) {

	so := &opt

	db, err := OpenBboltDB(PathGenerator.Cache(so.ConfigPath))
	if err != nil {
		return nil, fmt.Errorf("init bbolt cache failed: %w", err)
	}
	so.AddCloser("bbolt_db", db)

	httpListener, err := net.Listen("tcp", so.Host)
	if err != nil {
		return nil, err
	}
	so.AddCloser("http_listener", httpListener)

	so.Setting.AddObserver(config.ObserverFunc(func(s *pc.Setting) {
		log.Set(s.GetLogcat(), PathGenerator.Log(so.ConfigPath))
	}))

	fmt.Println(version.Art)
	log.Info("config", "path", so.ConfigPath, "grpc&http host", so.Host)

	so.Setting.AddObserver(config.ObserverFunc(sysproxy.Update()))
	so.Setting.AddObserver(config.ObserverFunc(func(s *pc.Setting) { dialer.DefaultInterfaceName = s.GetNetInterface() }))

	// proxy access point/endpoint
	node := node.NewNodes(PathGenerator.Node(so.ConfigPath))
	subscribe := node.Subscribe()
	tag := node.Tag()

	// make dns flow across all proxy chain
	dynamicProxy := netapi.NewDynamicProxy(direct.Default)

	// local,remote,bootstrap dns
	dns := AddComponent(so, "resolver", resolver.NewResolver(dynamicProxy))
	// bypass dialer and dns request
	st := AddComponent(so, "shunt", route.NewRoute(node.Outbound(), dns, opt.ProcessDumper))
	node.SetRuleTags(st.Tags)
	// connections' statistic & flow data
	stcs := AddComponent(so, "statistic", statistics.NewConnStore(cache.NewCache(db, "flow_data"), st))
	hosts := AddComponent(so, "hosts", resolver.NewHosts(stcs, st))
	// wrap dialer and dns resolver to fake ip, if use
	fakedns := AddComponent(so, "fakedns", resolver.NewFakeDNS(hosts, hosts, cache.NewCache(db, "fakedns_cache"), cache.NewCache(db, "fakedns_cachev6")))
	// dns server/tun dns hijacking handler
	dnsServer := AddComponent(so, "dnsServer", resolver.NewDNSServer(fakedns))
	// make dns flow across all proxy chain
	dynamicProxy.Set(fakedns)
	// inbound server
	_ = AddComponent(so, "inbound_listener",
		inbound.NewListener(dnsServer, fakedns))
	// tools
	tools := tools.NewTools(fakedns, opt.Setting, st.Update)
	mux := http.NewServeMux()

	app := &appapi.Components{
		Start:        so,
		Mux:          mux,
		HttpListener: httpListener,
		Tools:        tools,
		Node:         node,
		DB:           db,
		Subscribe:    subscribe,
		Connections:  stcs,
		Tag:          tag,
	}

	// http page
	web.Server(app)
	// grpc server
	app.RegisterGrpcService()

	return app, nil
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
