package node

import (
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"golang.org/x/exp/slices"
)

type manager struct {
	*node.Manager
	lock sync.RWMutex
}

func NewManager(m *node.Manager) *manager { return &manager{Manager: m} }

func (m *manager) GetNode(hash string) (*point.Point, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	p, ok := m.Nodes[hash]
	return p, ok
}

func (m *manager) GetNodeByName(group, name string) (*point.Point, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	z := m.GroupsV2[group]
	if z == nil {
		return nil, false
	}

	hash := z.NodesV2[name]
	if hash == "" {
		return nil, false
	}

	return m.GetNode(hash)
}

func (m *manager) AddNode(p *point.Point) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.Nodes == nil {
		m.Nodes = make(map[string]*point.Point)
	}
	if m.GroupsV2 == nil {
		m.GroupsV2 = make(map[string]*node.Nodes)
	}

	n, ok := m.GroupsV2[p.Group]
	if !ok {
		n = &node.Nodes{
			NodesV2: make(map[string]string),
		}
		m.GroupsV2[p.Group] = n
	}

	n.NodesV2[p.Name] = p.Hash
	m.Nodes[p.Hash] = p
}

func (n *manager) DeleteRemoteNodes(group string) {
	n.lock.Lock()
	defer n.lock.Unlock()

	m := n.Manager

	x, ok := m.GroupsV2[group]
	if !ok {
		return
	}

	for k, v := range x.NodesV2 {
		n, ok := m.Nodes[v]
		if ok && n.Origin != point.Origin_remote {
			continue
		}

		delete(x.NodesV2, k)
		delete(m.Nodes, v)
	}

	if len(x.NodesV2) == 0 {
		delete(m.GroupsV2, group)
	}
}

func (m *manager) GetManager() *node.Manager {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return m.Manager
}

func (m *manager) DeleteNode(hash string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	p, ok := m.Nodes[hash]
	if !ok {
		return
	}

	delete(m.Nodes, hash)
	delete(m.GroupsV2[p.Group].NodesV2, p.Name)
	if len(m.GroupsV2[p.Group].NodesV2) == 0 {
		delete(m.GroupsV2, p.Group)
	}
}

func (m *manager) AddTag(tag string, hash string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	_, ok := m.Manager.Nodes[hash]
	if !ok {
		return
	}

	if m.Manager.Tags == nil {
		m.Manager.Tags = make(map[string]*node.Tags)
	}

	z, ok := m.Manager.Tags[tag]
	if !ok {
		z = &node.Tags{
			Tag: tag,
		}
		m.Manager.Tags[tag] = z
	}

	if !slices.Contains(z.Hash, hash) {
		z.Hash = append(z.Hash, hash)
	}
}

func (m *manager) DeleteTag(tag string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.Manager.Tags != nil {
		delete(m.Manager.Tags, tag)
	}
}

func (m *manager) ExistTag(tag string) (*node.Tags, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if m.Manager.Tags != nil {
		t, ok := m.Manager.Tags[tag]
		return t, ok
	}

	return nil, false
}
