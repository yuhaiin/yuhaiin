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
	"strings"
	"syscall"

	"github.com/Asutorufa/yuhaiin/internal/config"
	simplehttp "github.com/Asutorufa/yuhaiin/internal/http"
	"github.com/Asutorufa/yuhaiin/internal/server"
	"github.com/Asutorufa/yuhaiin/internal/statistic"
	logw "github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	protonode "github.com/Asutorufa/yuhaiin/pkg/protos/node"
	protosttc "github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

var lis net.Listener

type Yuhaiin struct{}

func (Yuhaiin) Start(host, savepath, dnsServer, socks5server string) error {
	// ver := flag.Bool("v", false, "show version")
	// host := flag.String("host", "127.0.0.1:50051", "gRPC and http listen host")
	// savepath := flag.String("path", protoconfig.DefaultConfigDir(), "save data path")
	// flag.Parse()

	// if *ver {
	// fmt.Print(version.String())
	// return
	// }

	pc := pathConfig(savepath)

	f := logw.NewLogWriter(pc.logfile)
	defer f.Close()
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	log.SetOutput(io.MultiWriter(f, os.Stdout))

	log.Println("\n\n\nsave config at:", pc.dir)
	log.Println("gRPC and http listen at:", host)

	// lock := error.Must(lockfile.NewLock(pc.lockfile, host))
	// defer lock.UnLock()

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

	grpcserver := grpc.NewServer()

	setting := config.NewConfig(pc.config)
	settings, err := setting.Load(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	if dnsServer != "" {
		if settings.Dns == nil {
			settings.Dns = &protoconfig.DnsSetting{}
		}

		settings.Dns.Server = dnsServer
	}

	if socks5server != "" {
		if settings.Server == nil {
			settings.Server = &protoconfig.Server{}
		}

		if settings.Server.Servers == nil {
			settings.Server.Servers = make(map[string]*protoconfig.ServerProtocol)
		}

		settings.Server.Servers["socks5"] = &protoconfig.ServerProtocol{
			Name: "socks5",
			Protocol: &protoconfig.ServerProtocol_Socks5{
				Socks5: &protoconfig.Socks5{
					Host: socks5server,
				},
			},
		}
	}
	if _, err = setting.Save(context.TODO(), settings); err != nil {
		return err
	}

	grpcserver.RegisterService(&protoconfig.ConfigDao_ServiceDesc, setting)

	// * net.Conn/net.PacketConn -> nodeManger -> BypassManager&statis/connection manager -> listener
	nodes := node.NewNodes(pc.node)
	grpcserver.RegisterService(&protonode.NodeManager_ServiceDesc, nodes)

	app := statistic.NewRouter(nodes)
	setting.AddObserver(app)
	grpcserver.RegisterService(&protosttc.Connections_ServiceDesc, app.Statistic())

	listener := server.NewListener(app.Proxy())
	setting.AddObserver(listener)
	defer listener.Close()

	mux := http.NewServeMux()
	simplehttp.Httpserver(mux, nodes, app.Statistic(), setting)

	// h2c for grpc insecure mode
	return http.Serve(lis, h2c.NewHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
				grpcserver.ServeHTTP(w, r)
			} else {
				mux.ServeHTTP(w, r)
			}
		}), &http2.Server{}))
}

func (Yuhaiin) Stop() {
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
