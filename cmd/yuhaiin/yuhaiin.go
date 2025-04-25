package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/app"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

func run(args []string) error {
	flag := flag.NewFlagSet("yuhaiin", flag.ExitOnError)
	host := flag.String("host", "0.0.0.0:50051", "gRPC and http listen host")
	username := flag.String("u", "", "username")
	password := flag.String("p", "", "password")
	path := flag.String("path", configuration.DataDir.Load(), "save data path")
	webdir := flag.String("eweb", "", "external web page")
	// pprof := flag.Bool("pgo", false, "enables CPU profiling")
	if err := flag.Parse(args); err != nil {
		return err
	}

	if *webdir != "" && os.Getenv("EXTERNAL_WEB") == "" {
		os.Setenv("EXTERNAL_WEB", *webdir)
	}

	lis, err := net.Listen("tcp", *host)
	if err != nil {
		return err
	}

	setting := config.NewJsonDB(app.PathGenerator.Config(*path))

	var grpcOpts []grpc.ServerOption

	var auth *app.Auth
	if *username != "" || *password != "" {
		auth = app.NewAuth(*username, *password)
		grpcOpts = append(grpcOpts, grpc.UnaryInterceptor(auth.GrpcAuth()))
	}

	grpcserver := grpc.NewServer(grpcOpts...)

	fmt.Println(version.Art)

	app, err := app.Start(&app.StartOptions{
		ConfigPath:     *path,
		Auth:           auth,
		BypassConfig:   setting,
		ResolverConfig: setting,
		InboundConfig:  setting,
		ChoreConfig:    setting,
		GRPCServer:     grpcserver,
		ProcessDumper:  getPorcessDumper(),
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := app.Close(); err != nil {
			log.Error("close app error", "err", err)
		}
	}()

	// if *pprof {
	// 	if close, err := StartCPUProfile(*path); err != nil {
	// 		log.Error("start cpu profile error", "err", err)
	// 	} else {
	// 		defer close()
	// 	}
	// }

	ctx, cancel := context.WithCancelCause(context.TODO())
	defer cancel(nil)

	go func() {
		// h2c for grpc insecure mode
		err := http.Serve(lis, h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug("http request", "host", r.Host, "method", r.Method, "path", r.URL.Path)

			if grpcserver != nil && r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
				grpcserver.ServeHTTP(w, r)
			} else {
				app.Mux.ServeHTTP(w, r)
			}
		}), &http2.Server{}))
		if err != nil {
			cancel(err)
		}
	}()

	// listen system signal
	ctx, ncancel := signal.NotifyContext(ctx, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer ncancel()

	return wait(ctx, lis)
}

var wait = func(ctx context.Context, lis net.Listener) error {
	<-ctx.Done()
	var err error
	if lis != nil {
		err = lis.Close()
	}
	return errors.Join(err, ctx.Err())
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

var (
	addrV4Loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	addrV6Loopback = netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
)

func (processDumperImpl) ProcessName(network string, src, dst netapi.Address) (netapi.Process, error) {
	if src.IsFqdn() || dst.IsFqdn() {
		return netapi.Process{}, fmt.Errorf("source or destination address is not ip")
	}

	ip := src.(netapi.IPAddress).AddrPort()
	to := dst.(netapi.IPAddress).AddrPort()

	if to.Addr().IsUnspecified() {
		if ip.Addr().Is4() {
			to = netip.AddrPortFrom(addrV4Loopback, uint16(dst.Port()))
		} else {
			to = netip.AddrPortFrom(addrV6Loopback, uint16(dst.Port()))
		}
	}

	return netlink.FindProcessName(network, ip, to)
}

// func StartCPUProfile(path string) (func(), error) {
// 	pgoFile := filepath.Join(path, "yuhaiin.pgo")
// 	previousFile := filepath.Join(path, "previous.pgo")
// 	err := ypprof.MergePgoTo([]string{pgoFile, previousFile}, previousFile)
// 	if err != nil {
// 		log.Error("merge pgo error", "err", err)
// 	}

// 	f, err := os.Create(pgoFile)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// runtime.SetCPUProfileRate(100)
// 	if err := pprof.StartCPUProfile(f); err != nil {
// 		f.Close()
// 		return nil, err
// 	}

// 	log.Info("start cpu profiling")

// 	return func() {
// 		pprof.StopCPUProfile()
// 		f.Close() // error handling omitted for example
// 		err := ypprof.MergePgoTo([]string{pgoFile, previousFile}, previousFile)
// 		if err != nil {
// 			log.Error("merge pgo error", "err", err)
// 		}
// 	}, nil
// }
