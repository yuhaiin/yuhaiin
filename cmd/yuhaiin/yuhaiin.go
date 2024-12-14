package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/internal/appapi"
	"github.com/Asutorufa/yuhaiin/pkg/config"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	ypprof "github.com/Asutorufa/yuhaiin/pkg/pprof"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

func run(args []string) error {
	flag := flag.NewFlagSet("yuhaiin", flag.ExitOnError)
	host := flag.String("host", "0.0.0.0:50051", "gRPC and http listen host")
	path := flag.String("path", pc.DefaultConfigDir(), "save data path")
	webdir := flag.String("eweb", "", "external web page")
	pprof := flag.Bool("pgo", false, "enables CPU profiling")
	if err := flag.Parse(args); err != nil {
		return err
	}

	if *webdir != "" && os.Getenv("EXTERNAL_WEB") == "" {
		os.Setenv("EXTERNAL_WEB", *webdir)
	}

	setting := config.NewConfig(app.PathGenerator.Config(*path))
	grpcserver := grpc.NewServer()

	app, err := app.Start(appapi.Start{
		ConfigPath:    *path,
		Host:          *host,
		BypassConfig:  setting,
		Setting:       setting,
		GRPCServer:    grpcserver,
		ProcessDumper: getPorcessDumper(),
	})
	if err != nil {
		return err
	}
	defer app.Close()

	if *pprof {
		if close, err := StartCPUProfile(*path); err != nil {
			log.Error("start cpu profile error", "err", err)
		} else {
			defer close()
		}
	}

	errChan := make(chan error)

	go func() {
		// h2c for grpc insecure mode
		errChan <- http.Serve(app.HttpListener, h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug("http request", "host", r.Host, "method", r.Method, "path", r.URL.Path)

			if grpcserver != nil && r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
				grpcserver.ServeHTTP(w, r)
			} else {
				app.Mux.ServeHTTP(w, r)
			}
		}), &http2.Server{}))
	}()

	// listen system signal
	signChannel := make(chan os.Signal, 1)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	return wait(app, errChan, signChannel)
}

var wait = func(app *appapi.Components, errChan chan error, signChannel chan os.Signal) error {
	select {
	case err := <-errChan:
		return err
	case <-signChannel:
		if app.HttpListener != nil {
			app.HttpListener.Close()
		}
		return nil
	}
}

func getPorcessDumper() netapi.ProcessDumper {
	if !configuration.ProcessDumper {
		return nil
	}

	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		return processDumperImpl{}
	}

	return nil
}

type processDumperImpl struct{}

func (processDumperImpl) ProcessName(network string, src, dst netapi.Address) (string, error) {
	if src.IsFqdn() || dst.IsFqdn() {
		return "", fmt.Errorf("source or destination address is not ip")
	}

	ip := src.(netapi.IPAddress).IP()
	to := dst.(netapi.IPAddress).IP()

	if to.IsUnspecified() {
		if ip.To4() != nil {
			to = net.IPv4(127, 0, 0, 1)
		} else {
			to = net.IPv6loopback
		}
	}

	return netlink.FindProcessName(network, ip, src.Port(), to, dst.Port())
}

func StartCPUProfile(path string) (func(), error) {
	pgoFile := filepath.Join(path, "yuhaiin.pgo")
	previousFile := filepath.Join(path, "previous.pgo")
	err := ypprof.MergePgoTo([]string{pgoFile, previousFile}, previousFile)
	if err != nil {
		log.Error("merge pgo error", "err", err)
	}

	f, err := os.Create(pgoFile)
	if err != nil {
		return nil, err
	}

	// runtime.SetCPUProfileRate(100)
	if err := pprof.StartCPUProfile(f); err != nil {
		f.Close()
		return nil, err
	}

	log.Info("start cpu profiling")

	return func() {
		pprof.StopCPUProfile()
		f.Close() // error handling omitted for example
		err := ypprof.MergePgoTo([]string{pgoFile, previousFile}, previousFile)
		if err != nil {
			log.Error("merge pgo error", "err", err)
		}
	}, nil
}
