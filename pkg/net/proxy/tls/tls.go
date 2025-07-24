package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/google/uuid"
)

type Tls struct {
	netapi.Proxy
	tlsConfigPool clientConfigPools
}

func init() {
	register.RegisterPoint(NewClient)
}

type clientConfigPools []cliectConfigPool

func (p clientConfigPools) getConfig() *tls.Config {
	if len(p) == 0 {
		return nil
	}
	return p[rand.IntN(len(p))].getConfig()
}

type cliectConfigPool interface {
	getConfig() *tls.Config
}

type fixedConfigPool struct {
	*tls.Config
}

func (f *fixedConfigPool) getConfig() *tls.Config {
	return f.Config
}

type patternServerNameConfigPool struct {
	config           *tls.Config
	serverNameSuffix string
}

func (p *patternServerNameConfigPool) getConfig() *tls.Config {
	c := p.config.Clone()
	c.ServerName = fmt.Sprintf("%s.%s", uuid.NewString(), p.serverNameSuffix)
	return c
}

type bilibiliMcdnPatternServerNameConfigPool struct {
	config           *tls.Config
	serverNameSuffix string
}

func (p *bilibiliMcdnPatternServerNameConfigPool) getConfig() *tls.Config {
	c := p.config.Clone()

	prefix := fmt.Sprintf("xy%dx%dx%dx%dxy", rand.IntN(255), rand.IntN(255), rand.IntN(255), rand.IntN(255))

	if rand.IntN(2) == 0 {
		ipv6 := net.IP{
			byte(rand.IntN(255)), byte(rand.IntN(255)),
			byte(rand.IntN(255)), byte(rand.IntN(255)),
			byte(rand.IntN(255)), byte(rand.IntN(255)),
			byte(rand.IntN(255)), byte(rand.IntN(255)),
			0, 0,
			0, 0,
			0, 0,
			byte(rand.IntN(255)), byte(rand.IntN(255)),
		}.String()

		ipv6 = strings.ReplaceAll(ipv6, ":", "y")

		prefix += ipv6 + "xy"
	}

	c.ServerName = fmt.Sprintf("%s.%s", prefix, p.serverNameSuffix)
	return c
}

func newConfigPool(serverName string, config *tls.Config) cliectConfigPool {
	if len(serverName) <= 2 {
		return &fixedConfigPool{config}
	}

	i := strings.IndexByte(serverName, '.')
	if i > 0 {
		switch serverName[:i] {
		case "<bilibili_mcdn>":
			return &bilibiliMcdnPatternServerNameConfigPool{
				config:           config,
				serverNameSuffix: serverName[i+1:],
			}

		case "*":
			return &patternServerNameConfigPool{
				config:           config,
				serverNameSuffix: serverName[i+1:],
			}
		}
	}

	c := config.Clone()
	c.ServerName = serverName

	return &fixedConfigPool{c}
}

func NewClient(c *protocol.TlsConfig, p netapi.Proxy) (netapi.Proxy, error) {
	tls := ParseTLSConfig(c)
	if tls == nil {
		return p, nil
	}

	var tlsConfigs []cliectConfigPool
	for _, v := range c.GetServerNames() {
		tlsConfigs = append(tlsConfigs, newConfigPool(v, tls))
	}

	if len(tlsConfigs) == 0 {
		tlsConfigs = append(tlsConfigs, &fixedConfigPool{tls})
	}

	return &Tls{
		tlsConfigPool: tlsConfigs,
		Proxy:         p,
	}, nil
}

func (t *Tls) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	c, err := t.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(c, t.tlsConfigPool.getConfig())

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func (t *Tls) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return t.Proxy.PacketConn(ctx, addr)
}

func init() {
	register.RegisterTransport(NewServer)
	register.RegisterTransport(NewTlsAutoServer)
}

func NewServer(c *listener.Tls, ii netapi.Listener) (netapi.Listener, error) {
	config, err := register.ParseTLS(c.GetTls())
	if err != nil {
		return nil, err
	}

	return netapi.NewListener(tls.NewListener(ii, config), ii), nil
}

type ServerCert struct {
	cert       *tls.Certificate
	ca         *cert.Ca
	servername string
	mu         sync.RWMutex
}

func (s *ServerCert) Cert() (*tls.Certificate, error) {
	s.mu.RLock()
	cert := s.cert
	s.mu.RUnlock()

	if cert != nil {
		return cert, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cert != nil {
		return s.cert, nil
	}

	servernames := []string{s.servername}
	if strings.HasPrefix(s.servername, "*.") {
		servernames = append(servernames, s.servername[2:])
	}

	sc, err := s.ca.GenerateServerCert(servernames...)
	if err != nil {
		return nil, err
	}

	tc, err := sc.TlsCert()
	if err != nil {
		return nil, err
	}

	s.cert = &tc

	return s.cert, nil
}

func TlsAutoConfig(ca *cert.Ca, nextProto []string, servername []string) *tls.Config {
	store := domain.NewDomainMapper[*ServerCert]()

	for _, v := range servername {
		store.Insert(v, &ServerCert{
			servername: v,
			ca:         ca,
		})
	}

	config := &tls.Config{
		NextProtos: nextProto,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if chi.ServerName == "" {
				return nil, fmt.Errorf("tls server name is empty")
			}

			cert, ok := store.SearchString(chi.ServerName)
			if !ok {
				return nil, fmt.Errorf("tls server name not found")
			}

			return cert.Cert()
		},
	}

	return config
}

func NewTlsAutoServer(c *listener.TlsAuto, ii netapi.Listener) (netapi.Listener, error) {
	ca, err := cert.ParseCa(c.GetCaCert(), c.GetCaKey())
	if err != nil {
		return nil, err
	}

	config := TlsAutoConfig(ca, c.GetNextProtos(), c.GetServernames())

	if c.GetEch().GetEnable() {
		config.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{
			{
				Config:     ECHConfig(c.GetEch().GetConfig()),
				PrivateKey: []byte(c.GetEch().GetPrivateKey()),
			},
		}
	}

	return netapi.NewListener(tls.NewListener(ii, config), ii), nil
}

var tlsSessionCache = tls.NewLRUClientSessionCache(128)

func ParseTLSConfig(t *protocol.TlsConfig) *tls.Config {
	if t == nil || !t.GetEnable() {
		return nil
	}

	root, err := x509.SystemCertPool()
	if err != nil {
		log.Error("get x509 system cert pool failed, create new cert pool.", "err", err)
		root = x509.NewCertPool()
	}

	for i := range t.GetCaCert() {
		ok := root.AppendCertsFromPEM(t.GetCaCert()[i])
		if !ok {
			log.Error("add cert from pem failed.")
		}
	}

	var servername string
	if len(t.GetServerNames()) > 0 {
		servername = t.GetServerNames()[0]
	}

	echConfig := t.GetEchConfig()
	if len(echConfig) == 0 {
		echConfig = nil
	}

	if echConfig != nil {
		config, err := parseEchConfigListOrConfig(echConfig)
		if err != nil {
			log.Error("parse ech config failed.", "err", err)
		} else {
			echConfig = config
		}
	}

	return &tls.Config{
		ServerName:                     servername,
		RootCAs:                        root,
		NextProtos:                     t.GetNextProtos(),
		InsecureSkipVerify:             t.GetInsecureSkipVerify(),
		ClientSessionCache:             tlsSessionCache,
		EncryptedClientHelloConfigList: echConfig,
		// SessionTicketsDisabled: true,
	}
}

func parseEchConfigListOrConfig(echConfig []byte) ([]byte, error) {
	_, err := ParseECHConfigList(echConfig)
	if err != nil {
		_, err = ECHConfig(echConfig).Spec()
		if err == nil {
			echConfig, err = ECHConfigList([]ECHConfig{ECHConfig(echConfig)})
		}
	}
	if err != nil {
		return nil, err
	}

	return echConfig, nil
}
