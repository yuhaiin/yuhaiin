package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/components/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
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
	savepath := flag.String("path", pc.DefaultConfigDir(), "save data path")
	flag.Parse()

	if *ver {
		fmt.Print(version.String())
		return
	}

	/*
		bbolt will create db file lock, so here is useless
		lock := yerror.Must(lockfile.NewLock(app.PathGenerator.Lock(*savepath), *host))
		defer lock.UnLock()
	*/

	setting := config.NewConfig(app.PathGenerator.Config(*savepath))
	grpcserver := newGrpcServer()

	yerror.Must(struct{}{}, app.Start(
		app.StartOpt{
			ConfigPath:    *savepath,
			Host:          *host,
			Setting:       setting,
			GRPCServer:    grpcserver,
			ProcessDumper: processDumper,
		},
	))
	defer app.Close()

	errChan := make(chan error)

	go func() {
		// h2c for grpc insecure mode
		errChan <- http.Serve(app.HttpListener, h2c.NewHandler(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if grpcserver != nil && r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
					grpcserver.ServeHTTP(w, r)
				} else {
					app.Mux.ServeHTTP(w, r)
				}
			}), &http2.Server{}))
	}()

	// listen system signal
	signChannel := make(chan os.Signal)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	select {
	case err := <-errChan:
		log.Error("http server error", "err", err)
	case <-signChannel:
		if app.HttpListener != nil {
			app.HttpListener.Close()
		}
	}
}
