package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

type Tls struct {
	netapi.EmptyDispatch

	dialer       netapi.Proxy
	tlsConfig    []*tls.Config
	configLength int
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(c *protocol.TlsConfig, p netapi.Proxy) (netapi.Proxy, error) {
	var tlsConfigs []*tls.Config
	tls := register.ParseTLSConfig(c)
	if tls != nil {
		// if !tls.InsecureSkipVerify && tls.ServerName == "" {
		// 	tls.ServerName = c.Simple.GetHost()
		// }

		tlsConfigs = append(tlsConfigs, tls)

		if len(c.GetServerNames()) > 1 {
			for _, v := range c.GetServerNames()[1:] {
				tc := tls.Clone()
				tc.ServerName = v

				tlsConfigs = append(tlsConfigs, tc)
			}
		}
	}

	if len(tlsConfigs) == 0 {
		return p, nil
	}

	return &Tls{
		tlsConfig:    tlsConfigs,
		dialer:       p,
		configLength: len(tlsConfigs),
	}, nil
}

func (t *Tls) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	c, err := t.dialer.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	return tls.Client(c, t.tlsConfig[rand.IntN(t.configLength)]), nil
}

func (t *Tls) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return t.dialer.PacketConn(ctx, addr)
}

func (t *Tls) Close() error {
	return t.dialer.Close()
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

	lis, err := ii.Stream(context.TODO())
	if err != nil {
		return nil, err
	}
	return netapi.NewListener(tls.NewListener(lis, config), ii), nil
}

type ServerCert struct {
	servername string
	mu         sync.RWMutex
	cert       *tls.Certificate
	ca         *cert.Ca
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

	sc, err := s.ca.GenerateServerCert(s.servername)
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

	lis, err := ii.Stream(context.TODO())
	if err != nil {
		return nil, err
	}

	return netapi.NewListener(tls.NewListener(lis, config), ii), nil
}
