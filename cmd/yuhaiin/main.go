package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	yuhaiin "github.com/Asutorufa/yuhaiin/internal"
	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/internal/lockfile"
	"github.com/Asutorufa/yuhaiin/internal/version"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

var processDumper listener.ProcessDumper
var newGrpcServer = func() *grpc.Server { return nil }

func main() {
	ver := flag.Bool("v", false, "show version")
	host := flag.String("host", "127.0.0.1:50051", "gRPC and http listen host")
	savepath := flag.String("path", protoconfig.DefaultConfigDir(), "save data path")
	flag.Parse()

	if *ver {
		fmt.Print(version.String())
		return
	}

	lock := yerror.Must(lockfile.NewLock(yuhaiin.PathGenerator.Lock(*savepath), *host))
	defer lock.UnLock()

	setting := config.NewConfig(yuhaiin.PathGenerator.Config(*savepath))
	grpcserver := newGrpcServer()

	resp := yerror.Must(
		yuhaiin.Start(
			yuhaiin.StartOpt{
				ConfigPath:    *savepath,
				Host:          *host,
				Setting:       setting,
				GRPCServer:    grpcserver,
				ProcessDumper: processDumper,
			},
		))
	defer resp.Close()

	// listen system signal
	signChannel := make(chan os.Signal, 1)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() bool {
		return (<-signChannel).String() != "" && resp.HttpListener != nil && resp.HttpListener.Close() != nil
	}()

	yerror.Must(struct{}{},
		// h2c for grpc insecure mode
		http.Serve(resp.HttpListener, h2c.NewHandler(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if grpcserver != nil && r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
					grpcserver.ServeHTTP(w, r)
				} else {
					resp.Mux.ServeHTTP(w, r)
				}
			}), &http2.Server{})))
}
