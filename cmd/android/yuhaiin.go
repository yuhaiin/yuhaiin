package yuhaiin

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	aconfig "github.com/Asutorufa/yuhaiin/cmd/android/config"
	"github.com/Asutorufa/yuhaiin/internal/config"
	simplehttp "github.com/Asutorufa/yuhaiin/internal/http"
	"github.com/Asutorufa/yuhaiin/internal/server"
	"github.com/Asutorufa/yuhaiin/internal/statistic"
	logw "github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GOPROXY=https://goproxy.cn,direct ANDROID_HOME=/mnt/data/ide/idea-Android-sdk/Sdk/ ANDROID_NDK_HOME=/mnt/dataHDD/android-ndk/android-ndk-r23b gomobile bind -o yuhaiin.aar -target=android ./

var lis net.Listener

type App struct{}

func (App) Start(host, savepath, dnsServer, socks5server, httpserver string,
	fakedns bool, fakednsIpRange string) error {
	pc := pathConfig(savepath)

	f := logw.NewLogWriter(pc.logfile)
	defer f.Close()
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	log.SetOutput(io.MultiWriter(f, os.Stdout))

	log.Println("\n\n\nsave config at:", pc.dir)
	log.Println("gRPC and http listen at:", host)

	var err error
	// create listener
	lis, err = net.Listen("tcp", host)
	if err != nil {
		return err
	}

	// listen system signal
	signChannel := make(chan os.Signal, 1)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() bool { return (<-signChannel).String() != "" && lis != nil && lis.Close() != nil }()

	setting := config.NewConfig(pc.config)
	settings, err := setting.Load(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	if settings.Dns == nil {
		settings.Dns = &protoconfig.DnsSetting{}
	}

	settings.Dns.Server = dnsServer
	settings.Dns.Fakedns = fakedns

	settings.Server.Servers = map[string]*protoconfig.ServerProtocol{
		"socks5": {
			Protocol: &protoconfig.ServerProtocol_Socks5{
				Socks5: &protoconfig.Socks5{
					Host: socks5server,
				},
			},
		},
		"http": {
			Protocol: &protoconfig.ServerProtocol_Http{
				Http: &protoconfig.Http{
					Host: httpserver,
				},
			},
		},
	}

	wrapSetting := aconfig.NewWrapSetting(setting, settings)

	// * net.Conn/net.PacketConn -> nodeManger -> BypassManager&statis/connection manager -> listener
	nodes := node.NewNodes(pc.node)
	// grpcserver.RegisterService(&protonode.NodeManager_ServiceDesc, nodes)

	_, ipRange, err := net.ParseCIDR(fakednsIpRange)
	if err != nil {
		return err
	}
	app := statistic.NewRouter(nodes, ipRange)
	defer app.Close()
	setting.AddObserver(app)

	listener := server.NewListener(app.Proxy())
	setting.AddObserver(listener)
	defer listener.Close()

	if _, err = setting.Save(context.TODO(), settings); err != nil {
		return err
	}

	mux := http.NewServeMux()
	simplehttp.Httpserver(mux, nodes, app.Statistic(), wrapSetting)
	return http.Serve(lis, mux)
}

func (App) Stop() {
	if lis != nil {
		lis.Close()
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
