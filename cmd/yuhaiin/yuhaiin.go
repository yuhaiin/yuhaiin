package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/app"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/managementauth"
	"github.com/Asutorufa/yuhaiin/pkg/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func run(args []string) error {
	flag := flag.NewFlagSet("yuhaiin", flag.ExitOnError)
	host := flag.String("host", "0.0.0.0:50051", "http listen host")
	https := flag.Bool("https", true, "enable HTTPS alongside HTTP on the same listen port")
	httpsCert := flag.String("https-cert", "", "TLS certificate PEM file (use with -https-key)")
	httpsKey := flag.String("https-key", "", "TLS private key PEM file (use with -https-cert)")
	httpsNames := flag.String("https-names", "", "comma-separated hostnames or IPs for the generated TLS certificate")
	username := flag.String("u", "", "username")
	password := flag.String("p", "", "password")
	path := flag.String("path", configuration.DataDir.Load(), "save data path")
	webdir := flag.String("eweb", "", "external web page")
	nfsMode := flag.Bool("nfs-mode", false, "use SQLite settings for NFS/network filesystems")
	// pprof := flag.Bool("pgo", false, "enables CPU profiling")
	if err := flag.Parse(args); err != nil {
		return err
	}
	storagesqlite.SetNFSMode(*nfsMode)

	if *webdir != "" && os.Getenv("EXTERNAL_WEB") == "" {
		os.Setenv("EXTERNAL_WEB", *webdir)
	}

	lis, err := net.Listen("tcp", *host)
	if err != nil {
		return err
	}
	var tlsCertificate tls.Certificate
	var tlsFingerprint string
	var generatedTLSCertificate bool
	if *https {
		tlsCertificate, tlsFingerprint, generatedTLSCertificate, err = loadManagementTLSCertificate(*path, *httpsCert, *httpsKey, *httpsNames)
		if err != nil {
			_ = lis.Close()
			return err
		}
	} else if *httpsCert != "" || *httpsKey != "" || *httpsNames != "" {
		_ = lis.Close()
		return errors.New("-https-cert, -https-key, and -https-names require -https")
	}

	setting := migrate.NewStateDB(paths.PathGenerator.State(*path))

	var auth *app.Auth
	if *username != "" || *password != "" {
		auth = app.NewAuth(*username, *password)
		log.Warn("legacy -u/-p management credentials are no longer accepted; use the web setup/login and remove these flags")
	}

	fmt.Println(version.Art)

	identities, err := managementauth.OpenRuntime(context.Background(), *path)
	if err != nil {
		_ = lis.Close()
		return err
	}
	defer identities.Close()
	app, err := app.Start(&app.StartOptions{
		ConfigPath:          *path,
		Auth:                auth,
		HTTPMiddleware:      identities.Middleware,
		ProxyAuthentication: identities.Proxy,
		UpstreamCredentials: identities.Upstream,
		StateStore:          setting,
		ProcessDumper:       getPorcessDumper(),
		Updater:             newUpdateInstaller(*path),
	})
	if err != nil {
		_ = lis.Close()
		return err
	}
	identities.Upstream.Changed = app.NodeRuntime.InvalidateCredential
	defer func() {
		if err := app.Close(); err != nil {
			log.Error("close app error", "err", err)
		}
	}()

	ctx, cancel := context.WithCancelCause(context.TODO())
	defer cancel(nil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protocol := "http"
		if r.TLS != nil {
			protocol = "https"
		}
		log.Debug("management request", "protocol", protocol, "host", r.Host, "method", r.Method, "path", r.URL.Path)
		app.Mux.ServeHTTP(w, r)
	})
	httpHandler := http.Handler(handler)
	serverListener := net.Listener(lis)
	server := &http.Server{Handler: httpHandler}
	if *https {
		httpHandler = redirectRemoteHTTPToHTTPS(handler, lis.Addr())
		server.Handler = httpHandler
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{tlsCertificate},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}
		serverListener = newProtocolListener(lis, server.TLSConfig)
		if generatedTLSCertificate {
			fmt.Fprintf(os.Stderr, "Management HTTPS generated a self-signed certificate; its private key is stored in %s/management-tls.pem.\n", *path)
		}
		fmt.Fprintln(os.Stderr, "Management HTTP and HTTPS share this listener:")
		for _, address := range managementHTTPSURLs(lis.Addr()) {
			fmt.Fprintf(os.Stderr, "  %s\n", address)
		}
		fmt.Fprintf(os.Stderr, "TLS certificate SHA-256 fingerprint: %s\n", tlsFingerprint)
		if generatedTLSCertificate {
			fmt.Fprintln(os.Stderr, "If the browser warns about the self-signed certificate, compare this fingerprint before continuing.")
		}
	}
	go func() {
		if err := server.Serve(serverListener); err != nil {
			cancel(err)
		}
	}()

	// listen system signal
	ctx, ncancel := signal.NotifyContext(ctx, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer ncancel()

	return wait(ctx, serverListener)
}

var wait = func(ctx context.Context, listeners ...net.Listener) error {
	<-ctx.Done()
	var err error
	for _, listener := range listeners {
		if listener != nil {
			err = errors.Join(err, listener.Close())
		}
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
