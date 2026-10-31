package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/servicehost"
	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/startuphealth"
	updatecmd "github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/update"
	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/app"
	recovery "github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	managementauth "github.com/Asutorufa/yuhaiin/pkg/management/auth"
	"github.com/Asutorufa/yuhaiin/pkg/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	updatemaintenance "github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

// Tests replace this only to terminate a subprocess at an actual startup boundary.
var recoveryStartupCheckpoint func(string)

func run(args []string) (resultErr error) {
	flag := flag.NewFlagSet("yuhaiin", flag.ExitOnError)
	host := flag.String("host", "0.0.0.0:50051", "http listen host")
	https := flag.Bool("https", true, "enable HTTPS alongside HTTP on the same listen port")
	httpsCert := flag.String("https-cert", "", "TLS certificate PEM file (use with -https-key)")
	httpsKey := flag.String("https-key", "", "TLS private key PEM file (use with -https-cert)")
	httpsManaged := flag.String("https-certificate-id", "", "already issued managed HTTPS certificate ID (exclusive with -https-cert/-https-key/-https-names)")
	httpsNames := flag.String("https-names", "", "comma-separated hostnames or IPs for the generated TLS certificate")
	username := flag.String("u", "", "username")
	password := flag.String("p", "", "password")
	path := flag.String("path", configuration.DataDir.Load(), "save data path")
	webdir := flag.String("eweb", "", "external web page")
	nfsMode := flag.Bool("nfs-mode", false, "use SQLite settings for NFS/network filesystems")
	restoredStartup := flag.Bool("recovery-startup", true, "adopt explicitly restored startup inputs; disable only for reviewed host configuration changes")
	// pprof := flag.Bool("pgo", false, "enables CPU profiling")
	if err := flag.Parse(args); err != nil {
		return err
	}
	if *httpsManaged != "" && (!*https || *httpsCert != "" || *httpsKey != "" || *httpsNames != "") {
		return errors.New("-https-certificate-id requires HTTPS and excludes certificate file/generated-name flags")
	}
	storagesqlite.SetNFSMode(*nfsMode)
	absolutePath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}
	*path = absolutePath

	// Serialize the server with offline snapshot/restore before creating TLS
	// identity material or opening either database. Closing leaves the inode.
	lifecycle, err := lockfile.Acquire(filepath.Join(*path, ".configuration.lock"))
	if err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	if lifecycle != nil {
		defer lifecycle.Close()
	} else {
		log.Warn("offline recovery coordination is unavailable on this platform")
	}

	if *webdir != "" && os.Getenv("EXTERNAL_WEB") == "" {
		os.Setenv("EXTERNAL_WEB", *webdir)
	}
	tlsMode := "disabled"
	if *https {
		tlsMode = "self_signed"
		if *httpsCert != "" {
			tlsMode = "files"
		}
		if *httpsManaged != "" {
			tlsMode = "managed"
		}
	}
	startupInputs := contractrecovery.Runtime{ManagementAuth: true, ManagementTLS: tlsMode,
		ManagedCertificateID: *httpsManaged, CertificateFile: *httpsCert, KeyFile: *httpsKey, ListenAddress: *host, ExternalWebDirectory: os.Getenv("EXTERNAL_WEB")}
	startupInputs.WorkingDirectory, err = os.Getwd()
	if err != nil {
		return err
	}
	if *restoredStartup && lifecycle != nil {
		resolved, adopted, err := recovery.ResolveStartupInputs(context.Background(), *path, lifecycle, startupInputs)
		if err != nil {
			return err
		}
		if adopted {
			if !resolved.ManagementAuth {
				return errors.New("restored startup requires a host supporting the archived management authentication mode")
			}
			if err := os.Chdir(resolved.WorkingDirectory); err != nil {
				return err
			}
			if err := os.Setenv("EXTERNAL_WEB", resolved.ExternalWebDirectory); err != nil {
				return err
			}
			*https = resolved.ManagementTLS != "disabled"
			*httpsCert, *httpsKey = resolved.CertificateFile, resolved.KeyFile
			*httpsManaged = resolved.ManagedCertificateID
			if resolved.ListenAddress != "" {
				*host = resolved.ListenAddress
			} else {
				resolved.ListenAddress = *host
			}
			startupInputs = resolved
		}
	}
	recoveryStartup, err := recovery.PrepareStartup(*path, lifecycle, startupInputs)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	updateStartup, err := updatemaintenance.PrepareStartup(context.Background(), *path, executable, recoveryStartup.BackupID(), recoveryStartup.InstanceID())
	if err != nil {
		_ = recoveryStartup.Abort()
		return err
	}
	recoveryComplete := false
	defer func() {
		if !recoveryComplete {
			resultErr = errors.Join(resultErr, recoveryStartup.Abort())
		}
	}()

	lis, err := net.Listen("tcp", *host)
	if err != nil {
		return err
	}
	defer lis.Close()
	var tlsCertificate tls.Certificate
	var tlsFingerprint string
	var generatedTLSCertificate bool
	if *https && *httpsManaged == "" {
		tlsCertificate, tlsFingerprint, generatedTLSCertificate, err = loadManagementTLSCertificate(*path, *httpsCert, *httpsKey, *httpsNames)
		if err != nil {
			_ = lis.Close()
			return err
		}
	} else if !*https && (*httpsCert != "" || *httpsKey != "" || *httpsNames != "" || *httpsManaged != "") {
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
		ConfigPath:            *path,
		DelayCertificateStart: true,
		Auth:                  auth,
		HTTPMiddleware:        identities.Middleware,
		ProxyAuthentication:   identities.Proxy,
		UpstreamCredentials:   identities.Upstream,
		StateStore:            setting,
		ProcessDumper:         getPorcessDumper(),
		Updater:               updatecmd.NewInstaller(*path),
		RecoveryStartupID:     recoveryStartup.ID(),
		RecoveryMaintenance:   servicehost.NewRecoveryMaintainer(*path),
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
	var managementTLSConfig *tls.Config
	if app.Certificates != nil {
		config, pair, bindErr := app.Certificates.BindManagement(context.Background(), *httpsManaged)
		if bindErr != nil {
			return bindErr
		}
		if pair != nil {
			managementTLSConfig, tlsCertificate = config, *pair
			tlsFingerprint = fmt.Sprintf("%x", sha256.Sum256(pair.Certificate[0]))
		}
	} else if *httpsManaged != "" {
		return errors.New("managed management HTTPS requires the SQLite certificate manager")
	}
	if recoveryStartup != nil && recoveryStartupCheckpoint != nil {
		recoveryStartupCheckpoint("after_application")
	}
	if err := startuphealth.RecordRuntime(context.Background(), setting, startupInputs); err != nil {
		if recoveryStartup != nil || *httpsManaged != "" {
			return err
		}
		log.Warn("recovery startup metadata unavailable; offline backup will require explicit inputs", "err", err)
	}

	// Prune only under this process's lifecycle owner, before management can
	// change policy. Current/pending and last-result copies remain pinned.
	if options, err := app.Backup.Get(context.Background()); err == nil && options.Recovery != nil && options.Recovery.LocalPoints != nil && options.Recovery.LocalPoints.Enabled {
		cleanupContext, stopCleanup := context.WithTimeout(context.Background(), 5*time.Second)
		_, cleanupErr := recovery.PrunePointsWithLifecycle(cleanupContext, *path, lifecycle, *options.Recovery.LocalPoints)
		stopCleanup()
		if cleanupErr != nil {
			log.Warn("local rollback-copy cleanup did not complete; retained data remains private")
		}
	}

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
	defer server.Close()
	if *https {
		httpHandler = redirectRemoteHTTPToHTTPS(handler, lis.Addr())
		server.Handler = httpHandler
		server.TLSConfig = managementTLSConfig
		if server.TLSConfig == nil {
			server.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{tlsCertificate},
				MinVersion:   tls.VersionTLS12,
				NextProtos:   []string{"h2", "http/1.1"},
			}
		}
		serverListener = newProtocolListener(lis, server.TLSConfig)
		if generatedTLSCertificate {
			fmt.Fprintf(os.Stderr, "Management HTTPS generated a self-signed certificate; its private key is stored in %s/management-tls.pem.\n", *path)
		}
		fmt.Fprintln(os.Stderr, "Management HTTP and HTTPS share this listener:")
		addresses := managementHTTPSURLs(lis.Addr())
		if *httpsManaged != "" {
			addresses = nil
			for _, name := range tlsCertificate.Leaf.DNSNames {
				if !strings.HasPrefix(name, "*.") {
					addresses = append(addresses, "https://"+net.JoinHostPort(name, strconv.Itoa(lis.Addr().(*net.TCPAddr).Port)))
				}
			}
			fmt.Fprintf(os.Stderr, "Managed HTTPS requires a hostname covered by: %s\n", strings.Join(tlsCertificate.Leaf.DNSNames, ", "))
		}
		for _, address := range addresses {
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
	if recoveryStartup != nil || updateStartup != nil {
		healthContext, healthCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer healthCancel()
		if err := app.RecoveryStartupHealth(healthContext); err != nil {
			return err
		}
		var certificate *tls.Certificate
		if *https {
			certificate = &tlsCertificate
		}
		if err := startuphealth.CheckListener(healthContext, lis.Addr(), certificate); err != nil {
			return err
		}
		if err := recoveryStartup.Complete(); err != nil {
			return err
		}
		var leaf []byte
		if certificate != nil && len(certificate.Certificate) > 0 {
			leaf = certificate.Certificate[0]
		}
		if err := updateStartup.Complete(healthContext, lis.Addr().String(), leaf); err != nil {
			return err
		}
	}
	recoveryComplete = true
	if *httpsManaged != "" {
		verificationContext, stopVerification := context.WithTimeout(ctx, 65*time.Second)
		err := updateStartup.AwaitVerification(verificationContext)
		stopVerification()
		if err != nil {
			return err
		}
	}
	if app.Certificates != nil {
		if err := app.Certificates.Start(ctx); err != nil {
			return err
		}
	}

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
