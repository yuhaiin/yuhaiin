package node

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"google.golang.org/protobuf/proto"
)

type manager struct {
	*node.Manager
	mu sync.RWMutex
}

func NewManager(m *node.Manager) *manager { return &manager{Manager: m} }

func (m *manager) GetNode(hash string) (*point.Point, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.Manager.GetNodes()[hash]
	return p, ok
}

func (m *manager) GetNodeByName(group, name string) (*point.Point, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	z := m.Manager.GetGroupsV2()[group]
	if z == nil {
		return nil, false
	}

	hash := z.GetNodesV2()[name]
	if hash == "" {
		return nil, false
	}

	return m.GetNode(hash)
}

func (mm *manager) AddNode(p *point.Point) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	m := mm.Manager

	if m.GetNodes() == nil {
		m.SetNodes(make(map[string]*point.Point))
	}
	if m.GetGroupsV2() == nil {
		m.SetGroupsV2(make(map[string]*node.Nodes))
	}

	mm.refreshHash(p)

	n, ok := m.GetGroupsV2()[p.GetGroup()]
	if !ok {
		nn := &node.Nodes_builder{
			NodesV2: make(map[string]string),
		}
		n = nn.Build()
		m.GetGroupsV2()[p.GetGroup()] = n
	}

	n.GetNodesV2()[p.GetName()] = p.GetHash()
	m.GetNodes()[p.GetHash()] = p
}

func (n *manager) refreshHash(p *point.Point) {
	p.SetHash("")
	p.SetHash(fmt.Sprintf("%x", sha256.Sum256([]byte(p.String()))))

	for i := 6; i <= len(p.GetHash()); i++ {
		if _, ok := n.Manager.GetNodes()[p.GetHash()[:i]]; !ok {
			p.SetHash(p.GetHash()[:i])
			break
		}
	}
}

func (n *manager) DeleteRemoteNodes(group string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	m := n.Manager

	x, ok := m.GetGroupsV2()[group]
	if !ok {
		return
	}

	for k, v := range x.GetNodesV2() {
		n, ok := m.GetNodes()[v]
		if ok && n.GetOrigin() != point.Origin_remote {
			continue
		}

		delete(x.GetNodesV2(), k)
		delete(m.GetNodes(), v)
	}

	if len(x.GetNodesV2()) == 0 {
		delete(m.GetGroupsV2(), group)
	}
}

func (m *manager) GetManager() *node.Manager {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.Manager
}

func (mm *manager) DeleteNode(hash string) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	m := mm.Manager

	p, ok := m.GetNodes()[hash]
	if !ok {
		return
	}

	delete(m.GetNodes(), hash)
	delete(m.GetGroupsV2()[p.GetGroup()].GetNodesV2(), p.GetName())
	if len(m.GetGroupsV2()[p.GetGroup()].GetNodesV2()) == 0 {
		delete(m.GetGroupsV2(), p.GetGroup())
	}
}

func (m *manager) AddTag(tag string, t pt.TagType, hash string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Manager.GetTags() == nil {
		m.Manager.SetTags(make(map[string]*pt.Tags))
	}

	var ok bool
	switch t {
	case pt.TagType_node:
		_, ok = m.Manager.GetNodes()[hash]
	case pt.TagType_mirror:
		if tag == hash {
			ok = false
		} else {
			_, ok = m.Manager.GetTags()[hash]
		}
	}
	if !ok {
		return
	}

	z, ok := m.Manager.GetTags()[tag]
	if !ok {
		z = (&pt.Tags_builder{
			Tag:  proto.String(tag),
			Type: t.Enum(),
		}).Build()
		m.Manager.GetTags()[tag] = z
	}

	if !slices.Contains(z.GetHash(), hash) {
		z.SetHash(append(z.GetHash(), hash))
	}
}

func (m *manager) DeleteTag(tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Manager.GetTags() != nil {
		delete(m.Manager.GetTags(), tag)
	}
}

func (m *manager) ExistTag(tag string) (*pt.Tags, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.Manager.GetTags() != nil {
		t, ok := m.Manager.GetTags()[tag]
		return t, ok
	}

	return nil, false
}
