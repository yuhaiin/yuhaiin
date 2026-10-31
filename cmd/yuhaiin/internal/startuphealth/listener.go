package startuphealth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Probe only the just-created local listener, with its exact leaf as a trust
// anchor. This cannot follow redirects, use a proxy or contact a remote target.
func CheckListener(ctx context.Context, address net.Addr, certificate *tls.Certificate) error {
	target, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return err
	}
	if target.Addr().IsUnspecified() {
		if target.Addr().Is6() {
			target = netip.AddrPortFrom(netip.IPv6Loopback(), target.Port())
		} else {
			target = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), target.Port())
		}
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target.String())
	}}
	defer transport.CloseIdleConnections()
	scheme := "http"
	if certificate != nil {
		if len(certificate.Certificate) == 0 {
			return errors.New("restored listener certificate is empty")
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return err
		}
		name := certificateName(leaf)
		if name == "" {
			return errors.New("restored listener certificate has no verifiable SAN")
		}
		roots := x509.NewCertPool()
		roots.AddCert(leaf)
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: name}
		scheme = "https"
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://localhost/", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode >= http.StatusInternalServerError {
		return errors.New("restored management listener returned a server error")
	}
	return nil
}

func certificateName(leaf *x509.Certificate) string {
	for _, name := range leaf.DNSNames {
		if suffix, wildcard := strings.CutPrefix(name, "*."); wildcard {
			name = "recovery-health." + suffix
		}
		if leaf.VerifyHostname(name) == nil {
			return name
		}
	}
	for _, address := range leaf.IPAddresses {
		if name := address.String(); leaf.VerifyHostname(name) == nil {
			return name
		}
	}
	return ""
}
