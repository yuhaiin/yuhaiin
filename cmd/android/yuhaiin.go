package yuhaiin

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	iconfig "github.com/Asutorufa/yuhaiin/internal/config"
	simplehttp "github.com/Asutorufa/yuhaiin/internal/http"
	"github.com/Asutorufa/yuhaiin/internal/server"
	"github.com/Asutorufa/yuhaiin/internal/statistic"
	logw "github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/config"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GOPROXY=https://goproxy.cn,direct ANDROID_HOME=/mnt/data/ide/idea-Android-sdk/Sdk/ ANDROID_NDK_HOME=/mnt/dataHDD/android-ndk/android-ndk-r23b gomobile bind -o yuhaiin.aar -target=android ./

type App struct {
	closers []func() error
	running chan struct{}

	node *node.Nodes
}

type Opts struct {
	Host       string
	Savepath   string
	Socks5     string
	Http       string
	SaveLogcat bool
	Block      string
	Proxy      string
	Direct     string
	DNS        *DNSSetting
}

type DNSSetting struct {
	Server         string
	Fakedns        bool
	FakednsIpRange string
	Remote         *DNS
	Local          *DNS
	Bootstrap      *DNS
}

type DNS struct {
	Host string
	// Type
	// 0: reserve
	// 1: udp
	// 2: tcp
	// 3: doh
	// 4: dot
	// 5: doq
	// 6: doh3
	Type          int32
	Proxy         bool
	Subnet        string
	TlsServername string
}

func (a *App) Start(opt *Opts) error {
	if a.running != nil {
		select {
		case <-a.running:
		default:
			log.Println("yuhaiin is already running")
			return nil
		}
	}

	a.closers = []func() error{
		func() error {
			if a.running != nil {
				close(a.running)
				a.running = nil
			}
			return nil
		},
	}

	pc := pathConfig(opt.Savepath)

	writes := []io.Writer{os.Stdout}
	if opt.SaveLogcat {
		f := logw.NewLogWriter(pc.logfile)
		a.closers = append(a.closers, f.Close)
		writes = append(writes, f)
	}
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	log.SetOutput(io.MultiWriter(writes...))

	log.Println("\n\n\nsave config at:", pc.dir)
	log.Println("gRPC and http listen at:", opt.Host)

	var err error
	// create listener
	lis, err := net.Listen("tcp", opt.Host)
	if err != nil {
		return err
	}
	a.closers = append(a.closers, lis.Close)

	// listen system signal
	signChannel := make(chan os.Signal, 1)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() bool { return (<-signChannel).String() != "" && a != nil && a.Stop() != nil }()

	fakeSetting := fakeSetting(opt, pc.config)

	// * net.Conn/net.PacketConn -> nodeManger -> BypassManager&statis/connection manager -> listener
	a.node = node.NewNodes(pc.node)

	_, ipRange, err := net.ParseCIDR(opt.DNS.FakednsIpRange)
	if err != nil {
		return err
	}
	app := statistic.NewRouter(a.node, ipRange)
	a.closers = append(a.closers, app.Close)
	fakeSetting.AddObserver(app)
	insert(app.Insert, opt.Block, &statistic.BLOCK)
	insert(app.Insert, opt.Proxy, &statistic.PROXY)
	insert(app.Insert, opt.Direct, &statistic.DIRECT)

	listener := server.NewListener(app.Proxy())
	fakeSetting.AddObserver(listener)
	a.closers = append(a.closers, listener.Close)

	mux := http.NewServeMux()
	simplehttp.Httpserver(mux, a.node, app.Statistic(), fakeSetting)
	go http.Serve(lis, mux)
	return nil
}

func (a *App) Stop() error {
	for _, closer := range a.closers {
		closer()
	}
	a.node = nil
	return nil
}

func (a *App) SaveNewBypass(link, dir string) error {
	r, err := http.Get(link)
	if err != nil {
		log.Println("get new bypass failed:", err)
		if a.node == nil {
			log.Println("node is nil")
			return err
		}
		r, err = (&http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					add, err := proxy.ParseAddress(network, addr)
					if err != nil {
						return nil, err
					}
					return a.node.Conn(add)
				},
			},
		}).Get(link)
		if err != nil {
			log.Println("get new bypass by proxy failed:", err)
			return err
		}
	}
	defer r.Body.Close()

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(dir, "yuhaiin.conf"), data, os.ModePerm)
}

func insert(f func(string, *statistic.MODE), rules string, mode *statistic.MODE) {
	for _, rule := range strings.Split(rules, "\n") {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		f(rule, mode)
	}
}

func pathConfig(configPath string) struct{ dir, lockfile, node, config, logfile string } {
	create := func(child ...string) string { return filepath.Join(append([]string{configPath}, child...)...) }
	config := struct{ dir, lockfile, node, config, logfile string }{
		dir: configPath, lockfile: create("LOCK"),
		node: create("node.json"), config: create("config.json"),
		logfile: create("log", "yuhaiin.log"),
	}

	if _, err := os.Stat(config.logfile); errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(filepath.Dir(config.logfile), os.ModePerm)
	}

	return config
}

func fakeSetting(opt *Opts, path string) *fakeSettings {
	settings := &protoconfig.Setting{
		Dns: &protoconfig.DnsSetting{
			Server:  opt.DNS.Server,
			Fakedns: opt.DNS.Fakedns,
			Remote: &protoconfig.Dns{
				Host:          opt.DNS.Remote.Host,
				Type:          protoconfig.DnsDnsType(opt.DNS.Remote.Type),
				Proxy:         opt.DNS.Remote.Proxy,
				Subnet:        opt.DNS.Remote.Subnet,
				TlsServername: opt.DNS.Remote.TlsServername,
			},
			Local: &protoconfig.Dns{
				Host:          opt.DNS.Local.Host,
				Type:          protoconfig.DnsDnsType(opt.DNS.Local.Type),
				Proxy:         opt.DNS.Local.Proxy,
				Subnet:        opt.DNS.Local.Subnet,
				TlsServername: opt.DNS.Local.TlsServername,
			},
			Bootstrap: &protoconfig.Dns{
				Host:          opt.DNS.Bootstrap.Host,
				Type:          protoconfig.DnsDnsType(opt.DNS.Bootstrap.Type),
				Proxy:         opt.DNS.Bootstrap.Proxy,
				Subnet:        opt.DNS.Bootstrap.Subnet,
				TlsServername: opt.DNS.Bootstrap.TlsServername,
			},
		},
		SystemProxy: &protoconfig.SystemProxy{},
		Server: &protoconfig.Server{
			Servers: map[string]*protoconfig.ServerProtocol{
				"socks5": {
					Protocol: &protoconfig.ServerProtocol_Socks5{
						Socks5: &protoconfig.Socks5{
							Host: opt.Socks5,
						},
					},
				},
				"http": {
					Protocol: &protoconfig.ServerProtocol_Http{
						Http: &protoconfig.Http{
							Host: opt.Http,
						},
					},
				},
			},
		},

		Bypass: &protoconfig.Bypass{
			Enabled:    true,
			BypassFile: filepath.Join(filepath.Dir(path), "yuhaiin.conf"),
		},
	}

	return newFakeSetting(settings)
}

type fakeSettings struct {
	config.UnimplementedConfigDaoServer
	setting *protoconfig.Setting
}

func newFakeSetting(setting *protoconfig.Setting) *fakeSettings {
	return &fakeSettings{setting: setting}
}

func (w *fakeSettings) Load(ctx context.Context, in *emptypb.Empty) (*protoconfig.Setting, error) {
	return w.setting, nil
}

func (w *fakeSettings) Save(ctx context.Context, in *protoconfig.Setting) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (w *fakeSettings) AddObserver(o iconfig.Observer) {
	if o != nil {
		o.Update(w.setting)
	}
}
