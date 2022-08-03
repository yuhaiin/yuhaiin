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
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

func main() {
	ver := flag.Bool("v", false, "show version")
	host := flag.String("host", "127.0.0.1:50051", "gRPC and http listen host")
	savepath := flag.String("path", protoconfig.DefaultConfigDir(), "save data path")
	flag.Parse()

	if *ver {
		fmt.Print(version.String())
		return
	}

	pc := yuhaiin.PathConfig(*savepath)
	lock := yerror.Must(lockfile.NewLock(pc.Lockfile, *host))
	defer lock.UnLock()

	setting := config.NewConfig(pc.Config)
	grpcserver := grpc.NewServer()

	resp := yerror.Must(
		yuhaiin.Start(
			yuhaiin.StartOpt{
				PathConfig: pc,
				Host:       *host,
				Setting:    setting,
				GRPCServer: grpcserver,
			},
		))
	defer resp.Close()

	// listen system signal
	signChannel := make(chan os.Signal, 1)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() bool {
		return (<-signChannel).String() != "" && resp.HttpListener != nil && resp.HttpListener.Close() != nil
	}()

	setting.AddObserver(config.NewObserver(sysproxy.Update))
	defer sysproxy.Unset()

	yerror.Must(struct{}{},
		// h2c for grpc insecure mode
		http.Serve(resp.HttpListener, h2c.NewHandler(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
					grpcserver.ServeHTTP(w, r)
				} else {
					resp.Mux.ServeHTTP(w, r)
				}
			}), &http2.Server{})))
}
