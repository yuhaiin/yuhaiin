package manager

import (
	"context"
	"crypto/tls"
	"errors"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
)

// TLSConfig validates references at configuration time. An unissued/expired
// resource can be saved, but its handshake fails closed until valid material is
// published. The callback uses the current atomic cache on each new handshake.
func (m *Manager) TLSConfig(ctx context.Context, ids []string) (*tls.Config, error) {
	if len(ids) == 0 || len(ids) > 32 {
		return nil, errors.New("listener requires 1–32 managed certificates")
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !contract.ValidID(id) || seen[id] {
			return nil, errors.New("invalid or duplicate managed certificate reference")
		}
		seen[id] = true
		if _, err := m.options.Store.Get(ctx, id); err != nil {
			return nil, errors.New("managed certificate reference is unavailable")
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.Cache.GetCertificate(ids), NextProtos: []string{"h2", "http/1.1"}}, nil
}
