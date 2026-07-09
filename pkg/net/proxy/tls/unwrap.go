package tls

import (
	"context"
	ctls "crypto/tls"
	"fmt"
	"math/rand/v2"
	"net"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterContractPoint("tls_termination", func(config contractnode.TLSTermination, p netapi.Proxy) (netapi.Proxy, error) {
		tlsConfig, err := ParseServerTLSConfig(serverConfigFromContract(config.TLS))
		if err != nil {
			return nil, err
		}
		return NewUnWrapTls(tlsConfig, p)
	})
}

func serverConfigFromContract(config contractnode.ServerTLS) ServerConfig {
	out := ServerConfig{
		Certificates:          certificatesFromContract(config.Certificates),
		NextProtos:            config.NextProtos,
		ServerNameCertificate: make(map[string]CertificateConfig, len(config.ServerNameCertificate)),
	}
	for name, cert := range config.ServerNameCertificate {
		out.ServerNameCertificate[name] = certificateFromContract(cert)
	}
	if len(out.ServerNameCertificate) == 0 {
		out.ServerNameCertificate = nil
	}
	return out
}

func certificatesFromContract(in []contractnode.Certificate) []CertificateConfig {
	out := make([]CertificateConfig, 0, len(in))
	for _, cert := range in {
		out = append(out, certificateFromContract(cert))
	}
	return out
}

func certificateFromContract(config contractnode.Certificate) CertificateConfig {
	return CertificateConfig{
		Cert:         config.Cert,
		Key:          config.Key,
		CertFilePath: config.CertFilePath,
		KeyFilePath:  config.KeyFilePath,
	}
}

type unWrapTls struct {
	netapi.Proxy
	config *ctls.Config
}

func NewUnWrapTls(config *ctls.Config, p netapi.Proxy) (netapi.Proxy, error) {
	return &unWrapTls{
		Proxy:  p,
		config: config,
	}, nil
}

type TerminationConfig struct {
	TLS ServerConfig `json:"tls"`
}

type ServerConfig struct {
	Certificates          []CertificateConfig          `json:"certificates,omitzero"`
	NextProtos            []string                     `json:"next_protos,omitzero"`
	ServerNameCertificate map[string]CertificateConfig `json:"serverNameCertificate,omitzero"`
}

type CertificateConfig struct {
	Cert         []byte `json:"cert,omitzero"`
	Key          []byte `json:"key,omitzero"`
	CertFilePath string `json:"cert_file_path,omitzero"`
	KeyFilePath  string `json:"key_file_path,omitzero"`
}

func ParseServerTLSConfig(config ServerConfig) (*ctls.Config, error) {
	certificates := parseCertificates(config.Certificates)
	searcher := parseServerNameCertificate(config.ServerNameCertificate)
	tlsConfig := &ctls.Config{
		NextProtos:   config.NextProtos,
		Certificates: certificates,
	}
	tlsConfig.GetCertificate = func(chi *ctls.ClientHelloInfo) (*ctls.Certificate, error) {
		if searcher != nil {
			addr, err := netapi.ParseAddressPort("tcp", chi.ServerName, 0)
			if err == nil {
				if cert, ok := searcher.SearchFqdn(addr); ok {
					return cert, nil
				}
			}
		}
		if len(tlsConfig.Certificates) != 0 {
			return &tlsConfig.Certificates[rand.IntN(len(tlsConfig.Certificates))], nil
		}
		return nil, fmt.Errorf("can't find certificate for %s", chi.ServerName)
	}
	return tlsConfig, nil
}

func parseCertificates(config []CertificateConfig) []ctls.Certificate {
	certs := make([]ctls.Certificate, 0, len(config))
	for _, item := range config {
		cert, err := x509KeyPair(item)
		if err != nil {
			log.Warn("key pair failed", "cert", item.Cert, "err", err)
			continue
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil
	}
	return certs
}

func parseServerNameCertificate(config map[string]CertificateConfig) *trie.Trie[*ctls.Certificate] {
	var searcher *trie.Trie[*ctls.Certificate]
	for name, item := range config {
		if name == "" {
			continue
		}
		cert, err := x509KeyPair(item)
		if err != nil {
			log.Warn("key pair failed", "cert", item.Cert, "err", err)
			continue
		}
		if net.ParseIP(name) == nil && name[0] != '*' {
			name = "*." + name
		}
		if searcher == nil {
			searcher = trie.NewTrie[*ctls.Certificate]()
		}
		searcher.Insert(name, &cert)
	}
	return searcher
}

func x509KeyPair(config CertificateConfig) (ctls.Certificate, error) {
	if config.CertFilePath != "" && config.KeyFilePath != "" {
		cert, err := ctls.LoadX509KeyPair(config.CertFilePath, config.KeyFilePath)
		if err != nil {
			log.Warn("load X509KeyPair error", "err", err)
		} else {
			return cert, nil
		}
	}
	return ctls.X509KeyPair(config.Cert, config.Key)
}

func (u *unWrapTls) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := u.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	if httpTermination, ok := conn.(interface{ SetTLSTermination(ok bool) }); ok {
		httpTermination.SetTLSTermination(true)
	}

	return newUnWrapConn(conn, u.config), nil
}

var _ net.Conn = (*unWrapConn)(nil)

type unWrapConn struct {
	net.Conn
	srcpipe *pipe.Conn
	dstpipe *pipe.Conn
	conn    *ctls.Conn
}

func newUnWrapConn(conn net.Conn, config *ctls.Config) *unWrapConn {
	src, dst := pipe.Pipe()

	tlsConn := ctls.Server(src, config)

	go relay.Relay(conn, tlsConn)

	h := &unWrapConn{
		Conn:    conn,
		srcpipe: src,
		dstpipe: dst,
		conn:    tlsConn,
	}

	return h
}

func (u *unWrapConn) Write(p []byte) (n int, err error) { return u.dstpipe.Write(p) }
func (u *unWrapConn) Read(p []byte) (n int, err error)  { return u.dstpipe.Read(p) }

func (u *unWrapConn) Close() error {
	u.conn.Close()
	u.srcpipe.Close()
	u.dstpipe.Close()
	return u.Conn.Close()
}
