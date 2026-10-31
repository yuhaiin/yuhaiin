package manager

import (
	"context"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

func (m *Manager) Providers(ctx context.Context) ([]contract.DNSProvider, error) {
	return m.options.Store.Providers(ctx)
}
func (m *Manager) SaveProvider(ctx context.Context, request contract.ProviderWrite) (contract.DNSProvider, error) {
	p, err := m.options.Store.SaveProvider(ctx, request.Provider, certificates.NewSecret([]byte(request.Token)))
	if err == nil {
		m.Wake()
	}
	return p, err
}
func (m *Manager) DeleteProvider(ctx context.Context, id string, revision uint64) error {
	err := m.options.Store.DeleteProvider(ctx, id, revision)
	if err == nil {
		m.Wake()
	}
	return err
}
