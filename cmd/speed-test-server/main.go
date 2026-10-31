// Command speed-test-server runs an explicitly configured HTTPS measurement
// endpoint. It is a separate administrator tool, never an application listener.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	address := flag.String("listen", "127.0.0.1:8443", "HTTPS listening address")
	cert := flag.String("certificate-file", "", "HTTPS certificate chain PEM file (required)")
	key := flag.String("key-file", "", "HTTPS private key PEM file (required)")
	upload := flag.Bool("enable-upload", false, "explicitly enable the bounded upload test endpoint")
	flag.Parse()
	if *cert == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "certificate-file and key-file are required; no plaintext fallback is supported")
		os.Exit(2)
	}
	server := &http.Server{Addr: *address, Handler: newMeasurementHandler(*upload), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 32 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS(*cert, *key) }()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "measurement HTTPS server failed:", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if server.Shutdown(shutdown) != nil {
			_ = server.Close()
		}
	}
}
