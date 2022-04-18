package main

import (
	"errors"
	"flag"
	"io"
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
	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	nodemanager "github.com/Asutorufa/yuhaiin/pkg/node"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	protostatistic "github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

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

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	host := flag.String("host", "127.0.0.1:50051", "gRPC and http listen host")
	savepath := flag.String("path", protoconfig.DefaultConfigDir(), "save data path")
	flag.Parse()

	pc := pathConfig(*savepath)

	f := logasfmt.NewLogWriter(pc.logfile)
	logasfmt.SetOutput(io.MultiWriter(append([]io.Writer{os.Stdout}, f)...))
	defer f.Close()

	logasfmt.Println("\n\n\nsave config at:", pc.dir)
	logasfmt.Println("gRPC and http listen at:", *host)

	lock := must(lockfile.NewLock(pc.lockfile, *host))
	defer lock.UnLock()

	// create listener
	lis := must(net.Listen("tcp", *host))

	// listen system signal
	signChannel := make(chan os.Signal, 1)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() bool { return (<-signChannel).String() != "" && lis != nil && lis.Close() != nil }()

	// * net.Conn/net.PacketConn -> nodeManger -> BypassManager&statis/connection manager -> listener
	nodes := nodemanager.NewNodeManager(pc.node)
	setting := config.NewConfig(pc.config)
	statistics := statistic.NewStatistic(setting, nodes)

	listener := server.NewListener(setting, statistics)
	defer listener.Close()

	sysproxy.Set(setting)
	defer sysproxy.Unset()

	mux := http.NewServeMux()
	simplehttp.Httpserver(mux, nodes, statistics, setting)

	grpcserver := grpc.NewServer()
	grpcserver.RegisterService(&node.NodeManager_ServiceDesc, nodes)
	grpcserver.RegisterService(&protoconfig.ConfigDao_ServiceDesc, setting)
	grpcserver.RegisterService(&protostatistic.Connections_ServiceDesc, statistics)

	must(struct{}{},
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
