package native

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native/control"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native/tlswrap"
)

var ErrAuth = errors.New("openvpn: authentication rejected")
var ErrRestart = errors.New("openvpn: server requested restart")

// Config contains only in-memory credentials; no profile directive can read
// host files, run scripts, or change host routes.
type Config struct {
	Gateway            string
	Network            string
	CACertPEM          string
	ClientCertPEM      string
	ClientKeyPEM       string
	ServerName         string
	Username           string
	Password           string
	TLSAuthKey         string
	TLSCryptKey        string
	KeyDirection       int
	Auth               string
	DataCiphers        []string
	InsecureSkipVerify bool
	MTU                int
	RenegotiateAfter   time.Duration
}

func (c *Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Gateway)
	if err != nil || host == "" || port == "" {
		return errors.New("openvpn: gateway must be host:port")
	}
	if c.Network == "" {
		c.Network = "udp"
	}
	if c.Network != "udp" && c.Network != "tcp" {
		return errors.New("openvpn: network must be udp or tcp")
	}
	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 1500) {
		return errors.New("openvpn: MTU must be between 576 and 1500")
	}
	if (c.ClientCertPEM == "") != (c.ClientKeyPEM == "") {
		return errors.New("openvpn: certificate and private key must be supplied together")
	}
	if c.ClientCertPEM == "" && c.Username == "" {
		return errors.New("openvpn: client certificate or username required")
	}
	for _, v := range []string{c.Username, c.Password, c.ServerName} {
		if len(v) > 4096 || strings.ContainsRune(v, 0) {
			return errors.New("openvpn: invalid credential or server name")
		}
	}
	if c.TLSAuthKey != "" && c.TLSCryptKey != "" {
		return errors.New("openvpn: tls-auth and tls-crypt are mutually exclusive")
	}
	if c.KeyDirection < -1 || c.KeyDirection > 1 {
		return errors.New("openvpn: key direction must be -1, 0, or 1")
	}
	if len(c.DataCiphers) == 0 {
		c.DataCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
	}
	c.DataCiphers = slices.Clone(c.DataCiphers)
	for _, name := range c.DataCiphers {
		if !slices.Contains([]string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}, name) {
			return fmt.Errorf("openvpn: unsupported data cipher %q", name)
		}
	}
	if c.RenegotiateAfter < 0 {
		return errors.New("openvpn: negative renegotiation interval")
	}
	if c.RenegotiateAfter == 0 {
		c.RenegotiateAfter = time.Hour
	}
	if _, err := c.wrapper(); err != nil {
		return fmt.Errorf("openvpn: control protection: %w", err)
	}
	return nil
}

// TLSConfig verifies the CA chain and server EKU. OpenVPN certificate identities
// commonly use a CN without a DNS SAN; ServerName opts into hostname checking.
func (c Config) TLSConfig() (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if c.CACertPEM != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(c.CACertPEM)) {
			return nil, errors.New("openvpn: invalid CA PEM")
		}
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.ServerName, RootCAs: roots,
		InsecureSkipVerify: c.InsecureSkipVerify || c.ServerName == ""}
	if c.ClientCertPEM != "" {
		cert, err := tls.X509KeyPair([]byte(c.ClientCertPEM), []byte(c.ClientKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("openvpn: client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	// With a server name, use Go's standard chain/EKU/hostname verification.
	// Without one, replace only the hostname requirement with CA/EKU checks;
	// OpenVPN CA-issued certificates commonly have no DNS SAN.
	if !c.InsecureSkipVerify && c.ServerName == "" {
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("openvpn: server sent no certificate")
			}
			intermediate := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediate.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots: roots, Intermediates: intermediate, DNSName: c.ServerName,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			return err
		}
	}
	return cfg, nil
}

func (c Config) wrapper() (control.Wrapper, error) {
	if c.TLSCryptKey == "" && c.TLSAuthKey == "" {
		return nil, nil
	}
	material := c.TLSAuthKey
	if c.TLSCryptKey != "" {
		material = c.TLSCryptKey
	}
	key, err := tlswrap.ParseStaticKey([]byte(material))
	if err != nil {
		return nil, err
	}
	if c.TLSCryptKey != "" {
		return tlswrap.NewCrypt(key, tlswrap.Inverse)
	}
	digest, err := tlswrap.ParseDigest(c.Auth)
	if err != nil {
		return nil, err
	}
	direction := tlswrap.Bidirectional
	switch c.KeyDirection {
	case 0:
		direction = tlswrap.Normal
	case 1:
		direction = tlswrap.Inverse
	}
	return tlswrap.NewAuth(key, direction, digest), nil
}
