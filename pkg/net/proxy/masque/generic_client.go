package masque

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/apernet/quic-go/http3"
)

func init() {
	register.RegisterContractPoint("masque", func(config contractnode.Masque, p netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(config, p)
	})
}

// NewClient constructs a standard RFC 9484 CONNECT-IP client. WARP's
// nonstandard protocol and draft datagrams are deliberately not used here.
func NewClient(config contractnode.Masque, p netapi.Proxy) (netapi.Proxy, error) {
	u, err := url.Parse(config.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || !strings.HasPrefix(u.Path, "/") || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("masque: url must be an absolute HTTPS URL with a path: %q", config.URL)
	}
	if config.Endpoint == "" {
		return nil, errors.New("masque: endpoint is required")
	}
	endpoint := config.Endpoint
	if _, _, err := net.SplitHostPort(endpoint); err != nil {
		endpoint = net.JoinHostPort(endpoint, "443")
	}
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("masque: resolve endpoint %q: %w", endpoint, err)
	}
	if len(config.LocalAddresses) == 0 {
		return nil, errors.New("masque: local_addresses is required")
	}
	addresses, err := wireguard.ParseEndpoints(config.LocalAddresses)
	if err != nil {
		return nil, fmt.Errorf("masque: local_addresses: %w", err)
	}
	mtu := int(config.MTU)
	if mtu == 0 {
		mtu = 1280
	}
	if mtu < 1280 || mtu > 65535 {
		return nil, errors.New("masque: mtu must be 1280..65535")
	}
	serverName := config.ServerName
	if serverName == "" {
		serverName = u.Hostname()
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: config.InsecureSkipVerify, //nolint:gosec // explicit user opt-in
		NextProtos:         []string{http3.NextProtoH3},
	}
	if config.CACertPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(config.CACertPEM)) {
			return nil, errors.New("masque: invalid CA certificate")
		}
		tlsConfig.RootCAs = roots
	}
	if (config.ClientCertPEM == "") != (config.ClientKeyPEM == "") {
		return nil, errors.New("masque: client certificate and key must be configured together")
	}
	if config.ClientCertPEM != "" {
		pair, err := tls.X509KeyPair([]byte(config.ClientCertPEM), []byte(config.ClientKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("masque: invalid client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	client, err := NewMasqueWithTransport(p, tlsConfig, addr, addresses, mtu, config.Transport)
	if err != nil {
		return nil, err
	}
	client.cloudflare = false
	client.requestURL = u.String()
	client.bearerToken = config.BearerToken
	return client, nil
}
