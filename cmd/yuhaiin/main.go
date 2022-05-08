package main

import (
	"errors"
	"flag"
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
	"github.com/Asutorufa/yuhaiin/internal/lockfile"
	"github.com/Asutorufa/yuhaiin/internal/server"
	"github.com/Asutorufa/yuhaiin/internal/statistic"
	logw "github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	protonode "github.com/Asutorufa/yuhaiin/pkg/protos/node"
	protosttc "github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/error"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

func main() {
	host := flag.String("host", "127.0.0.1:50051", "gRPC and http listen host")
	savepath := flag.String("path", protoconfig.DefaultConfigDir(), "save data path")
	flag.Parse()

	pc := pathConfig(*savepath)

	f := logw.NewLogWriter(pc.logfile)
	defer f.Close()
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	log.SetOutput(io.MultiWriter(f, os.Stdout))

	log.Println("\n\n\nsave config at:", pc.dir)
	log.Println("gRPC and http listen at:", *host)

	lock := error.Must(lockfile.NewLock(pc.lockfile, *host))
	defer lock.UnLock()

	// create listener
	lis := error.Must(net.Listen("tcp", *host))

	// listen system signal
	signChannel := make(chan os.Signal, 1)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() bool { return (<-signChannel).String() != "" && lis != nil && lis.Close() != nil }()

	grpcserver := grpc.NewServer()

	setting := config.NewConfig(pc.config)
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

	setting.AddObserver(config.WrapUpdate(sysproxy.Update))
	defer sysproxy.Unset()

	mux := http.NewServeMux()
	simplehttp.Httpserver(mux, nodes, app.Statistic(), setting)

	error.Must(struct{}{},
		// h2c for grpc insecure mode
		http.Serve(lis, h2c.NewHandler(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
					grpcserver.ServeHTTP(w, r)
				} else {
					mux.ServeHTTP(w, r)
				}
			}), &http2.Server{})))
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
