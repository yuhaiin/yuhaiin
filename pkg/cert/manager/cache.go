package manager

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

type certificateSnapshot struct{ pairs map[string]*tls.Certificate }

// Cache publishes immutable pairs. TLS admission performs no SQLite access,
// issuance or listener rebuild; existing connections retain their old pair.
type Cache struct {
	store    *certificates.Store
	mu       sync.Mutex
	snapshot atomic.Pointer[certificateSnapshot]
}

func NewCache(store *certificates.Store) *Cache {
	c := &Cache{store: store}
	c.snapshot.Store(&certificateSnapshot{pairs: map[string]*tls.Certificate{}})
	return c
}

// Reload is a management/startup operation. Invalid new material retains a
// previously verified certificate only for an unchanged DNS identity set.
// Missing resources are removed; one damaged certificate cannot disable others.
func (c *Cache) Reload(ctx context.Context, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	resources, err := c.store.List(ctx)
	if err != nil {
		return err
	}
	pairs := make(map[string]*tls.Certificate, len(resources))
	var failures []error
	for _, r := range resources {
		m, err := c.store.Material(ctx, r.Config.ID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		pair, err := ValidateMaterial(r.Config, m, now)
		if err == nil {
			pairs[r.Config.ID] = pair
			continue
		}
		failures = append(failures, fmt.Errorf("certificate %s is unavailable: %w", r.Config.ID, err))
		previous := c.snapshot.Load().pairs[r.Config.ID]
		if previous == nil {
			continue
		}
		// Validate the previous DER/key against the new resource's SANs and
		// roots as well. A changed trust policy must not reuse untrusted keys.
		retained := m
		retained.CertificatePEM = encodeChain(previous.Certificate)
		retained.PrivateKey, err = encodeSigner(previous.PrivateKey)
		if err == nil {
			if pair, err = ValidateMaterial(r.Config, retained, now); err == nil {
				pairs[r.Config.ID] = pair
			}
		}
	}
	c.snapshot.Store(&certificateSnapshot{pairs: pairs})
	return errors.Join(failures...)
}

// GetCertificate validates SNI against each explicitly referenced certificate.
// An expired or mismatched pair is never returned as a successful fallback.
func (c *Cache) GetCertificate(ids []string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	owned := append([]string(nil), ids...)
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello == nil || hello.ServerName == "" {
			return nil, errors.New("managed HTTPS requires SNI")
		}
		snapshot := c.snapshot.Load()
		now := time.Now()
		for _, id := range owned {
			pair := snapshot.pairs[id]
			if pair == nil || now.Before(pair.Leaf.NotBefore) || !now.Before(pair.Leaf.NotAfter) || pair.Leaf.VerifyHostname(hello.ServerName) != nil {
				continue
			}
			if err := hello.SupportsCertificate(pair); err == nil {
				return pair, nil
			}
		}
		return nil, errors.New("no valid managed certificate matches SNI and client capabilities")
	}
}
