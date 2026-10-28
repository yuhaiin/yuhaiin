package manager

import (
	"context"
	"crypto/tls"
	"errors"
	"time"
)

// BindManagement is called before serving the CLI management listener. Unlike
// a site Gateway, it requires usable material now so migration cannot lock an
// administrator out waiting for an initial issuance. Empty ID releases the
// previous guard when the host explicitly returns to its file/self-signed mode.
func (m *Manager) BindManagement(ctx context.Context, id string) (*tls.Config, *tls.Certificate, error) {
	if id == "" {
		return nil, nil, m.options.Store.BindManagement(ctx, "")
	}
	config, err := m.TLSConfig(ctx, []string{id})
	if err != nil {
		return nil, nil, err
	}
	pair := m.Cache.snapshot.Load().pairs[id]
	now := time.Now()
	if pair == nil || now.Before(pair.Leaf.NotBefore) || !now.Before(pair.Leaf.NotAfter) {
		return nil, nil, errors.New("management HTTPS requires an already issued, valid managed certificate")
	}
	if err := m.options.Store.BindManagement(ctx, id); err != nil {
		return nil, nil, err
	}
	return config, pair, nil
}
