package node

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
)

type manager struct {
	*node.Manager
	mu sync.RWMutex
}

func NewManager(m *node.Manager) *manager { return &manager{Manager: m} }

func (m *manager) GetNode(hash string) (*point.Point, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.Nodes[hash]
	return p, ok
}

func (m *manager) GetNodeByName(group, name string) (*point.Point, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
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
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Nodes == nil {
		m.Nodes = make(map[string]*point.Point)
	}
	if m.GroupsV2 == nil {
		m.GroupsV2 = make(map[string]*node.Nodes)
	}

	m.refreshHash(p)

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

func (n *manager) refreshHash(p *point.Point) {
	p.Hash = ""
	p.Hash = fmt.Sprintf("%x", sha256.Sum256([]byte(p.String())))

	for i := 6; i <= len(p.Hash); i++ {
		if _, ok := n.Manager.Nodes[p.Hash[:i]]; !ok {
			p.Hash = p.Hash[:i]
			break
		}
	}
}

func (n *manager) DeleteRemoteNodes(group string) {
	n.mu.Lock()
	defer n.mu.Unlock()

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
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.Manager
}

func (m *manager) DeleteNode(hash string) {
	m.mu.Lock()
	defer m.mu.Unlock()

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

func (m *manager) AddTag(tag string, t pt.TagType, hash string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Manager.Tags == nil {
		m.Manager.Tags = make(map[string]*pt.Tags)
	}

	var ok bool
	switch t {
	case pt.TagType_node:
		_, ok = m.Manager.Nodes[hash]
	case pt.TagType_mirror:
		if tag == hash {
			ok = false
		} else {
			_, ok = m.Manager.Tags[hash]
		}
	}
	if !ok {
		return
	}

	z, ok := m.Manager.Tags[tag]
	if !ok {
		z = &pt.Tags{
			Tag:  tag,
			Type: t,
		}
		m.Manager.Tags[tag] = z
	}

	if !slices.Contains(z.Hash, hash) {
		z.Hash = append(z.Hash, hash)
	}
}

func (m *manager) DeleteTag(tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Manager.Tags != nil {
		delete(m.Manager.Tags, tag)
	}
}

func (m *manager) ExistTag(tag string) (*pt.Tags, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.Manager.Tags != nil {
		t, ok := m.Manager.Tags[tag]
		return t, ok
	}

	return nil, false
}
