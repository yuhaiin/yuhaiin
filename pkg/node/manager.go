package node

import (
	"errors"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

type Manager struct {
	persist NodeStore
	store   *ProxyStore
}

func NewManager(path string) *Manager {
	return &Manager{
		persist: NewSQLiteContractNodeStore(path),
		store:   NewProxyStore(),
	}
}

func (m *Manager) Close() error {
	var err error
	if m.persist != nil {
		err = errors.Join(err, m.persist.Close())
	}
	return errors.Join(err, m.store.Close())
}

func (m *Manager) Subscribe() *Subscribe { return NewSubscribe(m, nil, nil) }
func (m *Manager) Outbound() *Outbound   { return &Outbound{manager: m} }
func (m *Manager) Store() *ProxyStore    { return m.store }

func (m *Manager) ReplaceRemoteContractNodes(group string, nodes []contractnode.Node) error {
	for _, node := range nodes {
		if node.ID != "" {
			m.store.Delete(node.ID)
		}
	}
	if err := m.persist.ReplaceRemoteContractNodes(group, nodes); err != nil {
		return err
	}
	return m.clearIdleProxy()
}

func (m *Manager) DeleteNode(id string) error {
	m.store.Delete(id)
	if err := m.persist.DeleteNode(id); err != nil {
		return err
	}
	return m.clearIdleProxy()
}

func (m *Manager) AddContractTag(tag, kind, target string) error {
	if err := m.persist.AddContractTag(tag, kind, target); err != nil {
		return err
	}
	return m.clearIdleProxy()
}

func (m *Manager) DeleteTag(tag string) error {
	if err := m.persist.DeleteTag(tag); err != nil {
		return err
	}
	return m.clearIdleProxy()
}

func (m *Manager) UsePoint(id string) error {
	if err := m.persist.UsePoint(id); err != nil {
		return err
	}
	return m.clearIdleProxy()
}

func (m *Manager) clearIdleProxy() error {
	used, err := m.persist.UsingContractPoints()
	if err != nil {
		return err
	}
	for k := range m.store.Range {
		if !used.Has(k) {
			m.store.Delete(k)
		}
	}
	return nil
}

func (m *Manager) getUsingPoints() *set.Set[string] {
	used, err := m.persist.UsingContractPoints()
	if err != nil {
		return set.NewSet[string]()
	}
	return used
}

func (m *Manager) GetUsingPoints() *set.Set[string] {
	return m.getUsingPoints()
}

func (m *Manager) GetContractTag(tag string) (string, []string, bool) {
	kind, targets, ok, err := m.persist.GetContractTag(tag)
	if err != nil {
		return "", nil, false
	}
	return kind, targets, ok
}
