package node

import (
	"errors"
	"iter"
	"slices"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
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

	return &Manager{db: db, store: NewProxyStore()}
}

func (m *Manager) GetStore() *ProxyStore { return m.store }

func (m *Manager) SaveNode(ps ...*point.Point) {
	if len(ps) == 0 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	nodes := m.node().GetManager().GetNodes()
	if nodes == nil {
		nodes = make(map[string]*point.Point)
		m.node().GetManager().SetNodes(nodes)
	}

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

		_, ok := nodes[p.GetHash()]
		if ok {
			m.store.Refresh(p)
		}

		nodes[p.GetHash()] = p
	}
}

func (m *Manager) DeleteRemoteNodes(group string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	manager := m.node().GetManager()

	for k, v := range manager.GetNodes() {
		if v.GetGroup() != group {
			continue
		}

		if v.GetOrigin() != point.Origin_remote {
			continue
		}

		delete(manager.GetNodes(), k)
		m.store.Delete(k)
	}
}

func (m *Manager) DeleteNode(hash string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	mgr := m.node().GetManager()

	_, ok := mgr.GetNodes()[hash]
	if !ok {
		return
	}

	delete(mgr.GetNodes(), hash)
	m.store.Delete(hash)
}

func (m *Manager) AddTag(tag string, t pt.TagType, hash string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	mgr := m.node().GetManager()
	if mgr.GetTags() == nil {
		mgr.SetTags(make(map[string]*pt.Tags))
	}

	var ok bool
	switch t {
	case pt.TagType_node:
		_, ok = mgr.GetNodes()[hash]
	case pt.TagType_mirror:
		if tag == hash {
			ok = false
		} else {
			_, ok = mgr.GetTags()[hash]
		}
	}
	if !ok {
		return
	}

	z, ok := mgr.GetTags()[tag]
	if !ok {
		z = (&pt.Tags_builder{
			Tag:  proto.String(tag),
			Type: t.Enum(),
		}).Build()
		mgr.GetTags()[tag] = z
	}

	if !slices.Contains(z.GetHash(), hash) {
		z.SetHash(append(z.GetHash(), hash))
	}

	m.clearIdleProxy()
}

func (m *Manager) DeleteTag(tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	mgr := m.node().GetManager()
	if mgr.GetTags() != nil {
		delete(mgr.GetTags(), tag)
	}

	m.clearIdleProxy()
}

func (m *Manager) SaveLinks(links ...*subscribe.Link) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.node().node.GetLinks() == nil {
		m.node().node.SetLinks(make(map[string]*subscribe.Link))
	}

	for _, link := range links {
		m.node().node.GetLinks()[link.GetName()] = link
	}
}

func (m *Manager) DeleteLink(name ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, name := range name {
		delete(m.node().node.GetLinks(), name)
	}
}

func (m *Manager) UsePoint(tcp, udp bool, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.node().GetNode(hash)
	if !ok {
		return errors.New("node not found")
	}

	if tcp {
		m.node().node.SetTcp(p)
	}

	if udp {
		m.node().node.SetUdp(p)
	}

	m.clearIdleProxy()
	return nil
}

func (m *Manager) clearIdleProxy() {
	usedHash := m.node().GetUsingPoints()

	for k := range m.store.Range {
		if !usedHash.Has(k) {
			m.store.Delete(k)
		}
	}
}

func (m *Manager) Close() error                                { return m.store.Close() }
func (m *Manager) Node() *Nodes                                { return &Nodes{manager: m} }
func (m *Manager) Subscribe() *Subscribe                       { return &Subscribe{n: m} }
func (m *Manager) Outbound() *outbound                         { return NewOutbound(m) }
func (m *Manager) Links() *link                                { return &link{m} }
func (m *Manager) Tag(ff func() iter.Seq[string]) gn.TagServer { return &tag{n: m, ruleTags: ff} }

func (d *Manager) Save() error {
	d.mu.Lock()
	err := d.db.Save()
	d.mu.Unlock()

	return err
}

func (d *Manager) node() *Node {
	return &Node{d.db.Data}
}

func (d *Manager) GetGroups() map[string][]*gn.NodesResponseNode {
	d.mu.RLock()
	defer d.mu.RUnlock()

	groups := map[string][]*gn.NodesResponseNode{}
	for _, v := range d.db.Data.GetManager().GetNodes() {
		group := v.GetGroup()
		if group == "" {
			group = "unknown"
		}

		groups[group] = append(groups[group], gn.NodesResponseNode_builder{
			Hash: proto.String(v.GetHash()),
			Name: proto.String(v.GetName()),
		}.Build())
	}

	return groups
}

func (d *Manager) GetNode(hash string) (*point.Point, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	p, ok := d.db.Data.GetManager().GetNodes()[hash]
	return p, ok
}

func (d *Manager) GetNow(tcp bool) *point.Point {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.node().GetNow(tcp)
}

func (d *Manager) GetTag(tag string) (*pt.Tags, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	t, ok := d.db.Data.GetManager().GetTags()[tag]
	return t, ok
}

func (d *Manager) GetTags() map[string]*pt.Tags {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.db.Data.GetManager().GetTags()
}

func (d *Manager) GetLinks() map[string]*subscribe.Link {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.db.Data.GetLinks()
}

func (d *Manager) GetLink(name string) (*subscribe.Link, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	l, ok := d.db.Data.GetLinks()[name]
	return l, ok
}

type Node struct {
	node *node.Node
}

func (n *Node) GetManager() *node.Manager {
	return n.node.GetManager()
}

func (m *Node) GetNode(hash string) (*point.Point, bool) {
	point, ok := m.node.GetManager().GetNodes()[hash]
	return point, ok
}

func (n *Node) GetNow(tcp bool) *point.Point {
	var p *point.Point
	if tcp {
		p = n.node.GetTcp()
	} else {
		p = n.node.GetUdp()
	}

	pp, ok := n.GetNode(p.GetHash())
	if ok {
		return pp
	}

	// get first node by group and name
	for _, v := range n.GetManager().GetNodes() {
		if v.GetGroup() != p.GetGroup() || v.GetName() != p.GetName() {
			continue
		}

		return v
	}

	return p
}

func (n *Node) GetUsingPoints() *set.Set[string] {
	set := set.NewSet[string]()

	tags := n.GetManager().GetTags()

	for _, v := range tags {
		if v.GetType() == pt.TagType_node {
			for _, hash := range v.GetHash() {
				set.Push(hash)
			}
		}
	}

	set.Push(n.GetNow(true).GetHash())
	set.Push(n.GetNow(false).GetHash())

	return set
}
