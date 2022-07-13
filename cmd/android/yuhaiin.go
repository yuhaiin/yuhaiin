package yuhaiin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

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

// GOPROXY=https://goproxy.cn,direct ANDROID_HOME=/mnt/data/ide/idea-Android-sdk/Sdk/ ANDROID_NDK_HOME=/mnt/dataHDD/android-ndk/android-ndk-r23b gomobile bind -target=android/amd64,android/arm64 -ldflags='-s -w' -trimpath -v -o yuhaiin.aar ./

type App struct {
	dialer proxy.Proxy
	lis    io.Closer

	lock   sync.Mutex
	closed chan struct{}
}

type Opts struct {
	Host       string      `json:"host"`
	Savepath   string      `json:"savepath"`
	Socks5     string      `json:"socks5"`
	Http       string      `json:"http"`
	SaveLogcat bool        `json:"save_logcat"`
	Bypass     *Bypass     `json:"bypass"`
	DNS        *DNSSetting `json:"dns"`
	TUN        *TUN        `json:"tun"`
}

type Bypass struct {
	// 0: bypass, 1: proxy, 2: direct, 3: block
	TCP int32 `json:"tcp"`
	// 0: bypass, 1: proxy, 2: direct, 3: block
	UDP int32 `json:"udp"`

	Block  string `json:"block"`
	Proxy  string `json:"proxy"`
	Direct string `json:"direct"`
}
type DNSSetting struct {
	Server         string `json:"server"`
	Fakedns        bool   `json:"fakedns"`
	FakednsIpRange string `json:"fakedns_ip_range"`
	Remote         *DNS   `json:"remote"`
	Local          *DNS   `json:"local"`
	Bootstrap      *DNS   `json:"bootstrap"`
}

type DNS struct {
	Host string `json:"host"`
	// Type
	// 0: reserve
	// 1: udp
	// 2: tcp
	// 3: doh
	// 4: dot
	// 5: doq
	// 6: doh3
	Type          int32  `json:"type"`
	Proxy         bool   `json:"proxy"`
	Subnet        string `json:"subnet"`
	TlsServername string `json:"tls_servername"`
}

type TUN struct {
	FD           int32  `json:"fd"`
	MTU          int32  `json:"mtu"`
	Gateway      string `json:"gateway"`
	DNSHijacking bool   `json:"dns_hijacking"`
	// Driver
	// 0: fdbased
	// 1: channel
	Driver int32 `json:"driver"`
}

func (a *App) Start(opt *Opts) error {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.closed != nil {
		select {
		case <-a.closed:
		default:
			return errors.New("yuhaiin is already running")
		}
	}

	errChan := make(chan error)
	defer close(errChan)

	go func() {
		pc := pathConfig(opt.Savepath)

		log.SetFlags(log.Lshortfile | log.LstdFlags)

		if opt.SaveLogcat {
			writes := []io.Writer{os.Stdout}
			f := logw.NewLogWriter(pc.logfile)
			defer f.Close()
			writes = append(writes, f)
			log.SetOutput(io.MultiWriter(writes...))
		}

		log.Println("\n\n\nsave config at:", pc.dir)
		log.Println("gRPC and http listen at:", opt.Host)

		// create listener
		lis, err := net.Listen("tcp", opt.Host)
		if err != nil {
			errChan <- err
		}
		defer lis.Close()

		fakeSetting := fakeSetting(opt, pc.config)

		// * net.Conn/net.PacketConn -> nodeManger -> BypassManager&statis/connection manager -> listener
		node := node.NewNodes(pc.node)
		a.dialer = node
		app := statistic.NewRouter(a.dialer)
		defer app.Close()
		fakeSetting.AddObserver(app)
		insert(app.Insert, opt.Bypass.Block, protoconfig.Bypass_block.String())
		insert(app.Insert, opt.Bypass.Proxy, protoconfig.Bypass_proxy.String())
		insert(app.Insert, opt.Bypass.Direct, protoconfig.Bypass_direct.String())

		listener := server.NewListener(app.Proxy(), app.DNSServer())
		defer listener.Close()
		fakeSetting.AddObserver(listener)

		mux := http.NewServeMux()
		simplehttp.Httpserver(mux, node, app.Statistic(), fakeSetting)
		srv := &http.Server{Handler: mux}
		defer srv.Close()
		a.lis = srv
		a.closed = make(chan struct{})
		defer close(a.closed)

		errChan <- nil

		srv.Serve(lis)
	}()
	return <-errChan
}

func (a *App) Stop() error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.closed == nil {
		return nil
	}
	var err error
	if a.lis != nil {
		err = a.lis.Close()
	}
	<-a.closed
	a.lis = nil
	a.dialer = nil
	a.closed = nil
	return err
}

func (a *App) Running() bool {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.closed == nil {
		return false
	}

	select {
	case <-a.closed:
		return false
	default:
		return true
	}
}

func (a *App) SaveNewBypass(link, dir string) error {
	r, err := http.Get(link)
	if err != nil {
		log.Println("get new bypass failed:", err)
		if a.dialer == nil {
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
					return a.dialer.Conn(add)
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

func insert(f func(string, string), rules string, mode string) {
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
			Server:         opt.DNS.Server,
			Fakedns:        opt.DNS.Fakedns,
			FakednsIpRange: opt.DNS.FakednsIpRange,
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
							Enabled: opt.Socks5 != "",
							Host:    opt.Socks5,
						},
					},
				},
				"http": {
					Protocol: &protoconfig.ServerProtocol_Http{
						Http: &protoconfig.Http{
							Enabled: opt.Http != "",
							Host:    opt.Http,
						},
					},
				},
				"tun": {
					Protocol: &protoconfig.ServerProtocol_Tun{
						Tun: &protoconfig.Tun{
							Enabled:       true,
							Name:          fmt.Sprintf("fd://%d", opt.TUN.FD),
							Mtu:           opt.TUN.MTU,
							Gateway:       opt.TUN.Gateway,
							DnsHijacking:  opt.TUN.DNSHijacking,
							SkipMulticast: true,
							Driver:        protoconfig.TunEndpointDriver(opt.TUN.Driver),
						},
					},
				},
			},
		},

		Bypass: &protoconfig.Bypass{
			Tcp:        protoconfig.BypassMode(opt.Bypass.TCP),
			Udp:        protoconfig.BypassMode(opt.Bypass.UDP),
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
