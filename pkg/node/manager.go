package node

import (
	"crypto/subtle"
	"errors"
	"iter"
	"slices"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"google.golang.org/protobuf/proto"
)

type Manager struct {
	db    *jsondb.DB[*node.Node]
	mu    sync.RWMutex
	store *ProxyStore
}

func NewManager(path string) *Manager {
	db := load(path)

	if db.Data.GetManager() == nil {
		db.Data.SetManager(&node.Manager{})
	}

	if db.Data.GetManager().GetNodes() == nil {
		db.Data.GetManager().SetNodes(make(map[string]*node.Point))
	}

	if db.Data.GetManager().GetTags() == nil {
		db.Data.GetManager().SetTags(make(map[string]*node.Tags))
	}

	if db.Data.GetManager().GetPublishes() == nil {
		db.Data.GetManager().SetPublishes(make(map[string]*node.Publish))
	}

	if db.Data.GetLinks() == nil {
		db.Data.SetLinks(make(map[string]*node.Link))
	}

	if db.Data.GetTcp() == nil {
		db.Data.SetTcp(&node.Point{})
	}

	if db.Data.GetUdp() == nil {
		db.Data.SetUdp(&node.Point{})
	}

	return &Manager{db: db, store: NewProxyStore()}
}

func (m *Manager) Close() error                                 { return m.store.Close() }
func (m *Manager) Node() *Nodes                                 { return &Nodes{manager: m} }
func (m *Manager) Subscribe() *Subscribe                        { return &Subscribe{n: m} }
func (m *Manager) Outbound() *Outbound                          { return &Outbound{manager: m} }
func (m *Manager) Tag(ff func() iter.Seq[string]) api.TagServer { return &tag{n: m, ruleTags: ff} }

func (m *Manager) Store() *ProxyStore { return m.store }

func (m *Manager) SaveNode(ps ...*node.Point) {
	if len(ps) == 0 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	nodes := m.getNodes()

	generateUUID := func() string {
		for {
			uuid := id.GenerateUUID().String()
			if _, ok := nodes[uuid]; !ok {
				return uuid
			}
		}
	}

	for _, p := range ps {
		if p.GetHash() == "" {
			p.SetHash(generateUUID())
		}

		if _, ok := nodes[p.GetHash()]; ok {
			m.store.Refresh(p)
		}

		m.storeNode(p.GetHash(), p)
	}
}

func (m *Manager) DeleteRemoteNodes(group string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for k, v := range m.getNodes() {
		if v.GetGroup() != group {
			continue
		}

		if v.GetOrigin() != node.Origin_remote {
			continue
		}

		m.deleteNode(k)
		m.store.Delete(k)
	}
}

func (m *Manager) DeleteNode(hash string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.getNodes()[hash]
	if !ok {
		return
	}

	m.deleteNode(hash)
	m.store.Delete(hash)
}

func (m *Manager) AddTag(tag string, t node.TagType, hash string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var ok bool
	switch t {
	case node.TagType_node:
		_, ok = m.getNodes()[hash]
	case node.TagType_mirror:
		if tag == hash {
			ok = false
		} else {
			_, ok = m.getTags()[hash]
		}
	}
	if !ok {
		return
	}

	z, ok := m.getTags()[tag]
	if !ok {
		z = (&node.Tags_builder{
			Tag:  proto.String(tag),
			Type: t.Enum(),
		}).Build()
		m.getTags()[tag] = z
	}

	if !slices.Contains(z.GetHash(), hash) {
		z.SetHash(append(z.GetHash(), hash))
	}

	m.clearIdleProxy()
}

func (m *Manager) DeleteTag(tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.deleteTag(tag)
	m.clearIdleProxy()
}

func (m *Manager) SaveLinks(links ...*node.Link) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, link := range links {
		m.getLinks()[link.GetName()] = link
	}
}

func (m *Manager) DeleteLink(name ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, name := range name {
		delete(m.getLinks(), name)
	}
}

func (m *Manager) UsePoint(hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.getNode(hash)
	if !ok {
		return errors.New("node not found")
	}

	m.db.Data.SetTcp(p)
	m.db.Data.SetUdp(p)

	m.clearIdleProxy()
	return nil
}

func (m *Manager) clearIdleProxy() {
	usedHash := m.getUsingPoints()

	for k := range m.store.Range {
		if !usedHash.Has(k) {
			m.store.Delete(k)
		}
	}
}

func (m *Manager) getUsingPoints() *set.Set[string] {
	set := set.NewSet[string]()

	tags := m.getTags()

	for _, v := range tags {
		if v.GetType() == node.TagType_node {
			for _, hash := range v.GetHash() {
				set.Push(hash)
			}
		}
	}

	set.Push(m.getNow(true).GetHash())
	set.Push(m.getNow(false).GetHash())

	return set
}

func (m *Manager) GetUsingPoints() *set.Set[string] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.getUsingPoints()
}

func (d *Manager) GetGroups() map[string][]*api.NodesResponse_Node {
	d.mu.RLock()
	defer d.mu.RUnlock()

	groups := map[string][]*api.NodesResponse_Node{}

	for _, v := range d.getNodes() {
		group := v.GetGroup()
		if group == "" {
			group = "unknown"
		}

		groups[group] = append(groups[group], api.NodesResponse_Node_builder{
			Hash: proto.String(v.GetHash()),
			Name: proto.String(v.GetName()),
		}.Build())
	}

	return groups
}

func (d *Manager) GetNode(hash string) (*node.Point, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	p, ok := d.getNodes()[hash]
	return p, ok
}

func (d *Manager) GetNow(tcp bool) *node.Point {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.getNow(tcp)
}

func (d *Manager) GetTag(tag string) (*node.Tags, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	t, ok := d.getTags()[tag]
	return t, ok
}

func (d *Manager) GetTags() map[string]*node.Tags {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.getTags()
}

func (d *Manager) GetLinks() map[string]*node.Link {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.getLinks()
}

func (d *Manager) GetLink(name string) (*node.Link, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	l, ok := d.getLinks()[name]
	return l, ok
}

func (m *Manager) getNode(hash string) (*node.Point, bool) {
	point, ok := m.getNodes()[hash]
	return point, ok
}

func (m *Manager) getNow(tcp bool) *node.Point {
	var p *node.Point
	if tcp {
		p = m.db.Data.GetTcp()
	} else {
		p = m.db.Data.GetUdp()
	}

	pp, ok := m.getNode(p.GetHash())
	if ok {
		return pp
	}

	// get first node by group and name
	for _, v := range m.getNodes() {
		if v.GetGroup() != p.GetGroup() || v.GetName() != p.GetName() {
			continue
		}

		return v
	}

	return p
}

func (d *Manager) Save() error {
	d.mu.Lock()
	err := d.db.Save()
	d.mu.Unlock()

	return err
}

func (d *Manager) getNodes() map[string]*node.Point {
	return d.db.Data.GetManager().GetNodes()
}

func (d *Manager) storeNode(hash string, node *node.Point) {
	d.getNodes()[hash] = node
}

func (d *Manager) deleteNode(hash string) {
	delete(d.getNodes(), hash)
}

func (d *Manager) getTags() map[string]*node.Tags {
	return d.db.Data.GetManager().GetTags()
}

func (m *Manager) deleteTag(tag string) {
	delete(m.getTags(), tag)
}

func (d *Manager) getLinks() map[string]*node.Link {
	return d.db.Data.GetLinks()
}

func (d *Manager) SavePublish(name string, publish *node.Publish) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.db.Data.GetManager().GetPublishes()[name] = publish
}

func (d *Manager) DeletePublish(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.db.Data.GetManager().GetPublishes(), name)
}

func (d *Manager) GetPublishes() map[string]*node.Publish {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.db.Data.GetManager().GetPublishes()
}

func (d *Manager) Publish(name, path, password string) []*node.Point {
	d.mu.RLock()
	defer d.mu.RUnlock()

	pub, ok := d.db.Data.GetManager().GetPublishes()[name]
	if !ok {
		return nil
	}

	if pub.GetPath() != path {
		return nil
	}

	if subtle.ConstantTimeCompare([]byte(pub.GetPassword()), []byte(password)) != 1 {
		return nil
	}

	ret := make([]*node.Point, 0, len(pub.GetPoints()))

	for _, v := range pub.GetPoints() {
		p, ok := d.getNode(v)
		if !ok {
			continue
		}

		ret = append(ret, p)
	}

	return ret
}
