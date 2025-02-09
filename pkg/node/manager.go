package node

import (
	"errors"
	"slices"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"github.com/Asutorufa/yuhaiin/pkg/utils/uuid"
	"google.golang.org/protobuf/proto"
)

type manager struct {
	db     *jsondb.DB[*node.Node]
	store  *ProxyStore
	mu     sync.RWMutex
	linkmu sync.RWMutex
	dbmu   sync.RWMutex
}

func NewManager(db *jsondb.DB[*node.Node], store *ProxyStore) *manager {
	if db.Data.GetManager() == nil {
		db.Data.SetManager(&node.Manager{})
	}

	return &manager{db: db, store: store}
}

func (m *manager) getManager() *node.Manager {
	return m.db.Data.GetManager()
}

func (m *manager) GetStore() *ProxyStore {
	return m.store
}

func (m *manager) GetNode(hash string) (*point.Point, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.getManager().GetNodes()[hash]
	return p, ok
}

func (o *manager) getNow(tcp bool) *point.Point {
	o.mu.RLock()
	var p *point.Point
	if tcp {
		p = o.db.Data.GetTcp()
	} else {
		p = o.db.Data.GetUdp()
	}
	o.mu.RUnlock()

	pp, ok := o.GetNode(p.GetHash())
	if ok {
		return pp
	}

	pp, ok = o.getNodeByName(p.GetGroup(), p.GetName())
	if ok {
		return pp
	}

	return p
}

func (m *manager) getNodeByName(group, name string) (*point.Point, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	z := m.getManager().GetGroupsV2()[group]
	if z == nil {
		return nil, false
	}

	hash := z.GetNodesV2()[name]
	if hash == "" {
		return nil, false
	}

	return m.GetNode(hash)
}

func (mm *manager) refreshGroup() {
	groups := map[string]*node.Nodes{}

	for _, v := range mm.getManager().GetNodes() {
		group := v.GetGroup()
		if group == "" {
			group = "unknown"
		}

		name := v.GetName()
		if name == "" {
			name = "unknown"
		}

		if _, ok := groups[group]; !ok {
			groups[group] = node.Nodes_builder{NodesV2: make(map[string]string)}.Build()
		}

		for {
			if _, ok := groups[group].GetNodesV2()[name]; !ok {
				groups[group].GetNodesV2()[name] = v.GetHash()
				break
			}
			name = name + "_" + uuid.Random().String()
		}
	}

	mm.getManager().SetGroupsV2(groups)
}

func (m *manager) isNodeNameExists(group, name string) (string, bool) {
	groups := m.getManager().GetGroupsV2()
	if groups == nil {
		return "", false
	}
	g := groups[group]
	if g == nil {
		return "", false
	}
	nodes := g.GetNodesV2()
	if nodes == nil {
		return "", false
	}
	hash, ok := nodes[name]
	return hash, ok
}

func (mm *manager) SaveNode(ps ...*point.Point) {
	if len(ps) == 0 {
		return
	}

	mm.mu.Lock()
	defer mm.mu.Unlock()

	if mm.getManager().GetNodes() == nil {
		mm.getManager().SetNodes(make(map[string]*point.Point))
	}

	type key struct {
		group string
		name  string
	}

	exists := map[key]string{}

	for _, p := range ps {
		key := key{
			group: p.GetGroup(),
			name:  p.GetName(),
		}

		if hash, ok := exists[key]; ok {
			log.Warn("node already exists", "group", p.GetGroup(), "name", p.GetName())
			p.SetHash(hash)
			continue
		}

		if p.GetHash() == "" {
			hash, ok := mm.isNodeNameExists(p.GetGroup(), p.GetName())
			if ok {
				p.SetHash(hash)
			} else {
				// generate hash
				for {
					uuid := uuid.Random().String()
					if _, ok := mm.getManager().GetNodes()[uuid]; !ok {
						p.SetHash(uuid)
						break
					}
				}
			}
		} else {
			mm.store.RefreshNode(p)
		}

		exists[key] = p.GetHash()
		mm.getManager().GetNodes()[p.GetHash()] = p
	}

	mm.refreshGroup()
}

func (n *manager) DeleteRemoteNodes(group string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	m := n.getManager()

	x, ok := m.GetGroupsV2()[group]
	if !ok {
		return
	}

	for _, v := range x.GetNodesV2() {
		node, ok := m.GetNodes()[v]
		if ok && node.GetOrigin() != point.Origin_remote {
			continue
		}

		delete(m.GetNodes(), v)
		n.store.Delete(v)
	}

	n.refreshGroup()
}

func (mm *manager) DeleteNode(hash string) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	m := mm.getManager()

	_, ok := m.GetNodes()[hash]
	if !ok {
		return
	}

	delete(m.GetNodes(), hash)
	mm.store.Delete(hash)
	mm.refreshGroup()
}

func (m *manager) AddTag(tag string, t pt.TagType, hash string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.getManager().GetTags() == nil {
		m.getManager().SetTags(make(map[string]*pt.Tags))
	}

	var ok bool
	switch t {
	case pt.TagType_node:
		_, ok = m.getManager().GetNodes()[hash]
	case pt.TagType_mirror:
		if tag == hash {
			ok = false
		} else {
			_, ok = m.getManager().GetTags()[hash]
		}
	}
	if !ok {
		return
	}

	z, ok := m.getManager().GetTags()[tag]
	if !ok {
		z = (&pt.Tags_builder{
			Tag:  proto.String(tag),
			Type: t.Enum(),
		}).Build()
		m.getManager().GetTags()[tag] = z
	}

	if !slices.Contains(z.GetHash(), hash) {
		z.SetHash(append(z.GetHash(), hash))
	}

	m.clearIdleProxy()
}

func (m *manager) DeleteTag(tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getManager().GetTags() != nil {
		delete(m.getManager().GetTags(), tag)
	}
	m.clearIdleProxy()
}

func (m *manager) ExistTag(tag string) (*pt.Tags, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.getManager().GetTags() != nil {
		t, ok := m.getManager().GetTags()[tag]
		return t, ok
	}

	return nil, false
}

func (m *manager) GetTags() map[string]*pt.Tags {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getManager().GetTags()
}

func (m *manager) SaveLinks(links ...*subscribe.Link) {
	m.linkmu.Lock()
	defer m.linkmu.Unlock()

	if m.db.Data.GetLinks() == nil {
		m.db.Data.SetLinks(make(map[string]*subscribe.Link))
	}

	for _, link := range links {
		m.db.Data.GetLinks()[link.GetName()] = link
	}
}

func (m *manager) GetLink(name string) (*subscribe.Link, bool) {
	m.linkmu.RLock()
	defer m.linkmu.RUnlock()
	link, ok := m.db.Data.GetLinks()[name]
	return link, ok
}

func (m *manager) DeleteLink(name ...string) {
	m.linkmu.Lock()
	defer m.linkmu.Unlock()
	for _, n := range name {
		delete(m.db.Data.GetLinks(), n)
	}
}

func (m *manager) GetLinks() map[string]*subscribe.Link {
	m.linkmu.RLock()
	defer m.linkmu.RUnlock()
	return m.db.Data.GetLinks()
}

func (m *manager) UsePoint(tcp, udp bool, hash string) error {
	p, ok := m.GetNode(hash)
	if !ok {
		return errors.New("node not found")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if tcp {
		m.db.Data.SetTcp(p)
	}

	if udp {
		m.db.Data.SetUdp(p)
	}

	m.clearIdleProxy()
	return nil
}

func (m *manager) Save() error {
	m.dbmu.Lock()
	defer m.dbmu.Unlock()

	return m.db.Save()
}

func (m *manager) clearIdleProxy() {
	usedHash := map[string]struct{}{}
	tags := m.GetTags()

	for _, v := range tags {
		if v.GetType() == pt.TagType_node {
			for _, hash := range v.GetHash() {
				usedHash[hash] = struct{}{}
			}
		}
	}

	usedHash[m.getNow(true).GetHash()] = struct{}{}
	usedHash[m.getNow(false).GetHash()] = struct{}{}

	for k := range m.store.Range {
		if _, ok := usedHash[k]; !ok {
			m.store.Delete(k)
		}
	}
}
