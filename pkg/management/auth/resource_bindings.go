package auth

import (
	"cmp"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func resourceBindings(records map[string]*proxyRecord) []trafficcontrol.IdentityBinding {
	result := make([]trafficcontrol.IdentityBinding, 0, len(records))
	for _, r := range records {
		result = append(result, trafficcontrol.IdentityBinding{UserID: r.UserID, CredentialID: r.ID, GroupIDs: r.groups})
	}
	slices.SortFunc(result, func(a, b trafficcontrol.IdentityBinding) int { return cmp.Compare(a.CredentialID, b.CredentialID) })
	return result
}

func resourceBindingsChanged(old, next map[string]*proxyRecord) bool {
	if len(old) != len(next) {
		return true
	}
	for id, r := range next {
		prior := old[id]
		if prior == nil || prior.UserID != r.UserID || !slices.Equal(prior.groups, r.groups) {
			return true
		}
	}
	return false
}

// The observer runs before a credential/membership snapshot becomes visible.
// It must not mutate/reload credentials or read authentication secrets. Existing
// authentication reads remain available while the observer prepares resources.
func (p *ProxyCredentials) SetResourceObserver(observer func([]trafficcontrol.IdentityBinding) error) error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()
	if observer != nil {
		p.mu.RLock()
		bindings := resourceBindings(p.records)
		p.mu.RUnlock()
		if err := observer(bindings); err != nil {
			return err
		}
	}
	p.mu.Lock()
	p.resourceObserver = observer
	p.mu.Unlock()
	return nil
}
