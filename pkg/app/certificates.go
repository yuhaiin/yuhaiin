package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"

	manager "github.com/Asutorufa/yuhaiin/pkg/cert/manager"
	"github.com/Asutorufa/yuhaiin/pkg/cert/manager/dnschallenge"
	"github.com/Asutorufa/yuhaiin/pkg/cert/manager/dnschallenge/cloudflare"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

type certificateProxy func(context.Context) (netapi.Proxy, error)
type certificateRuntime struct {
	*manager.Manager
	Challenges *manager.HTTPChallenges
	transport  *http.Transport
}

func (c *certificateRuntime) Close() error {
	err := c.Manager.Close()
	c.transport.CloseIdleConnections()
	return err
}

// certificateClient has no system/direct dial fallback or ambient HTTP proxy.
// Only the CA-specific client receives explicitly configured private CA roots.
func certificateClient(proxy certificateProxy, trust string) (*http.Client, *http.Transport, error) {
	var roots *x509.CertPool
	if trust != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(trust)) {
			return nil, nil, errors.New("invalid ACME trust roots")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			outbound, err := proxy(ctx)
			if err != nil {
				return nil, err
			}
			target, err := netapi.ParseAddress(network, address)
			if err != nil {
				return nil, err
			}
			return outbound.Conn(ctx, target)
		}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 2, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2}
	return &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport, nil
}

func newCertificateRuntime(ctx context.Context, store *certificates.Store, proxy certificateProxy, lookup func(context.Context, string) ([]string, error), available func(string) bool) (*certificateRuntime, error) {
	providerClient, transport, err := certificateClient(proxy, "")
	if err != nil {
		return nil, err
	}
	provider, err := cloudflare.New(providerClient)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	dns, err := dnschallenge.New(store, map[string]dnschallenge.Provider{"cloudflare": provider}, dnschallenge.Options{LookupTXT: lookup})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	challenges := manager.NewHTTPChallenges(available)
	controller, err := manager.New(manager.Options{Store: store, Cleanup: dns.Reconcile, RenewalInfo: func(ctx context.Context, c contract.Config, pair *tls.Certificate) (manager.RenewalInformation, error) {
		client, transport, err := certificateClient(proxy, c.TrustPEM)
		if err != nil {
			return manager.RenewalInformation{}, err
		}
		defer transport.CloseIdleConnections()
		return manager.FetchRenewalInfo(ctx, client, c, pair, time.Now())
	}, Report: func(code string) { log.Info("certificate lifecycle", "code", code) }, Issue: func(ctx context.Context, c contract.Config) (certificates.Material, error) {
		client, transport, err := certificateClient(proxy, c.TrustPEM)
		if err != nil {
			return certificates.Material{}, err
		}
		defer transport.CloseIdleConnections()
		issuer := manager.Issuer{Store: store, Client: client, Presenter: manager.Presenters{HTTP: manager.HTTPPresenter{Challenges: challenges}, DNS: dns}}
		return issuer.Issue(ctx, c)
	}})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	if err := controller.Cache.Reload(ctx, time.Now()); err != nil {
		log.Warn("some managed certificates are unavailable")
	}
	return &certificateRuntime{Manager: controller, Challenges: challenges, transport: transport}, nil
}
