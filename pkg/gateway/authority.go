package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

type CAStore interface {
	LoadCA(context.Context) ([]byte, []byte, uint64, error)
	SaveCA(context.Context, []byte, []byte, uint64) (uint64, error)
}
type authorityState struct {
	ca       *cert.Ca
	cache    *cert.Cache
	revision uint64
}

// Authority exposes public status and write-only management operations. The
// signer never enters Config, runtime status, diagnostics or a response DTO.
type Authority struct {
	store CAStore
	mu    sync.Mutex
	state atomic.Pointer[authorityState]
}

func NewAuthority(ctx context.Context, store CAStore) (*Authority, error) {
	a := &Authority{store: store}
	root, key, revision, err := store.LoadCA(ctx)
	if err != nil {
		return nil, err
	}
	if len(root) > 0 {
		ca, err := cert.ParseCa(root, key)
		if err != nil {
			return nil, errors.New("stored gateway CA is invalid")
		}
		a.state.Store(&authorityState{ca, cert.NewCache(ca, 512), revision})
	}
	return a, nil
}

func (a *Authority) Status() contract.CAStatus {
	s := a.state.Load()
	if s == nil {
		return contract.CAStatus{CacheCapacity: 512}
	}
	fingerprint := sha256.Sum256(s.ca.Cert.Raw)
	root, _ := s.ca.CertBytes()
	return contract.CAStatus{Present: true, Subject: s.ca.Cert.Subject.String(), Fingerprint: hex.EncodeToString(fingerprint[:]), NotBefore: s.ca.Cert.NotBefore, NotAfter: s.ca.Cert.NotAfter, CertificatePEM: string(root), CachedCertificates: s.cache.Len(), CacheCapacity: s.cache.Capacity(), Revision: s.revision}
}

func (a *Authority) Generate(ctx context.Context, revision uint64) (contract.CAStatus, error) {
	ca, err := cert.GenerateCa()
	if err != nil {
		return contract.CAStatus{}, err
	}
	return a.save(ctx, ca, revision)
}
func (a *Authority) Import(ctx context.Context, input contract.CAImport) (contract.CAStatus, error) {
	ca, err := cert.ParseCa([]byte(input.CertificatePEM), []byte(input.PrivateKeyPEM))
	if err != nil {
		return contract.CAStatus{}, errors.New("invalid CA certificate or private key")
	}
	if time.Now().Before(ca.Cert.NotBefore) || time.Until(ca.Cert.NotAfter) < 24*time.Hour {
		return contract.CAStatus{}, errors.New("CA must be valid now and for at least one day")
	}
	return a.save(ctx, ca, input.Revision)
}
func (a *Authority) save(ctx context.Context, ca *cert.Ca, revision uint64) (contract.CAStatus, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	root, err := ca.CertBytes()
	if err != nil {
		return contract.CAStatus{}, err
	}
	key, err := ca.PrivateKeyBytes()
	if err != nil {
		return contract.CAStatus{}, err
	}
	next, err := a.store.SaveCA(ctx, root, key, revision)
	if err != nil {
		return contract.CAStatus{}, err
	}
	a.state.Store(&authorityState{ca, cert.NewCache(ca, 512), next})
	return a.Status(), nil
}
func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	s := a.state.Load()
	if s == nil {
		return nil, errors.New("gateway CA has not been generated")
	}
	return s.cache.Get(x509.ECDSA, hostname(host))
}
