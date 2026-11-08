package tls

import "crypto/tls"

// ServerConfig returns the TLS settings shared by management HTTPS listeners:
// TLS 1.2 or newer, with HTTP/2 and HTTP/1.1 offered through ALPN.
func ServerConfig(certificate tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
}
