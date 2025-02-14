package node

import (
	"errors"
	"iter"
	"slices"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"github.com/Asutorufa/yuhaiin/pkg/utils/list"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

type Manager struct {
	db    *DB
	store *ProxyStore
}

func NewManager(path string) *Manager {
	db := load(path)

	if db.Data.GetManager() == nil {
		db.Data.SetManager(&node.Manager{})
	}

	return &Manager{db: &DB{db: db}, store: NewProxyStore()}
}

func (m *Manager) GetStore() *ProxyStore {
	return m.store
}

func (m *Manager) GetGroups() map[string]*node.Nodes {
	var groups map[string]*node.Nodes
	_ = m.db.View(func(n *Node) error {
		groups = n.GetManager().GetGroupsV2()
		return nil
	})
	return groups
}

func (m *Manager) GetNode(hash string) (*point.Point, bool) {
	var p *point.Point
	var ok bool
	_ = m.db.View(func(n *Node) error {
		p, ok = n.GetNode(hash)
		return nil
	})
	return p, ok
}

func (o *Manager) GetNow(tcp bool) *point.Point {
	var p *point.Point
	_ = o.db.View(func(n *Node) error {
		p = n.GetNow(tcp)
		return nil
	})

	return p
}

func (mm *Manager) refreshGroup() {
	_ = mm.db.Batch(func(n *Node) error {
		groups := map[string]*node.Nodes{}

		for _, v := range n.GetManager().GetNodes() {
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
				name = name + "_" + uuid.NewString()
			}
		}

		n.GetManager().SetGroupsV2(groups)

		return nil
	})

}

func (mm *Manager) SaveNode(ps ...*point.Point) {
	if len(ps) == 0 {
		return
	}

	_ = mm.db.Batch(func(n *Node) error {
		if n.GetManager().GetNodes() == nil {
			n.GetManager().SetNodes(make(map[string]*point.Point))
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
				hash, ok := n.isNodeNameExists(p.GetGroup(), p.GetName())
				if ok {
					p.SetHash(hash)
				} else {
					// generate hash
					for {
						uuid := uuid.NewString()
						if _, ok := n.GetManager().GetNodes()[uuid]; !ok {
							p.SetHash(uuid)
							break
						}
					}
				}
			} else {
				mm.store.Refresh(p)
			}

			exists[key] = p.GetHash()
			n.GetManager().GetNodes()[p.GetHash()] = p
		}

		return nil
	})

	mm.refreshGroup()
}

func (m *Manager) DeleteRemoteNodes(group string) {
	_ = m.db.Batch(func(n *Node) error {
		manager := n.GetManager()

		x, ok := manager.GetGroupsV2()[group]
		if !ok {
			return nil
		}

		for _, v := range x.GetNodesV2() {
			node, ok := manager.GetNodes()[v]
			if ok && node.GetOrigin() != point.Origin_remote {
				continue
			}

			delete(manager.GetNodes(), v)
			m.store.Delete(v)
		}

		return nil
	})

	m.refreshGroup()
}

func (mm *Manager) DeleteNode(hash string) {
	_ = mm.db.Batch(func(n *Node) error {
		m := n.GetManager()

		_, ok := m.GetNodes()[hash]
		if !ok {
			return nil
		}

		delete(m.GetNodes(), hash)
		mm.store.Delete(hash)

		return nil
	})

	mm.refreshGroup()
}

func (m *Manager) AddTag(tag string, t pt.TagType, hash string) {
	_ = m.db.Batch(func(n *Node) error {
		if n.GetManager().GetTags() == nil {
			n.GetManager().SetTags(make(map[string]*pt.Tags))
		}

		var ok bool
		switch t {
		case pt.TagType_node:
			_, ok = n.GetManager().GetNodes()[hash]
		case pt.TagType_mirror:
			if tag == hash {
				ok = false
			} else {
				_, ok = n.GetManager().GetTags()[hash]
			}
		}
		if !ok {
			return nil
		}

		z, ok := n.GetManager().GetTags()[tag]
		if !ok {
			z = (&pt.Tags_builder{
				Tag:  proto.String(tag),
				Type: t.Enum(),
			}).Build()
			n.GetManager().GetTags()[tag] = z
		}

		if !slices.Contains(z.GetHash(), hash) {
			z.SetHash(append(z.GetHash(), hash))
		}

		return nil
	})

	m.clearIdleProxy()
}

func (m *Manager) DeleteTag(tag string) {
	_ = m.db.Batch(func(n *Node) error {
		if n.GetManager().GetTags() != nil {
			delete(n.GetManager().GetTags(), tag)
		}

		return nil
	})

	m.clearIdleProxy()
}

func (m *Manager) ExistTag(tag string) (t *pt.Tags, ok bool) {
	_ = m.db.View(func(n *Node) error {
		if n.GetManager().GetTags() != nil {
			t, ok = n.GetManager().GetTags()[tag]
		}
		return nil
	})
	return
}

func (m *Manager) GetTags() map[string]*pt.Tags {
	var tags map[string]*pt.Tags
	_ = m.db.View(func(n *Node) error {
		tags = n.GetManager().GetTags()
		return nil
	})
	return tags
}

func (m *Manager) SaveLinks(links ...*subscribe.Link) {
	_ = m.db.Batch(func(n *Node) error {
		if n.node.GetLinks() == nil {
			n.node.SetLinks(make(map[string]*subscribe.Link))
		}

		for _, link := range links {
			n.node.GetLinks()[link.GetName()] = link
		}

		return nil
	})
}

func (m *Manager) GetLink(name string) (*subscribe.Link, bool) {
	var link *subscribe.Link
	var ok bool
	_ = m.db.View(func(n *Node) error {
		link, ok = n.node.GetLinks()[name]
		return nil
	})
	return link, ok
}

func (m *Manager) DeleteLink(name ...string) {
	_ = m.db.Batch(func(n *Node) error {
		for _, name := range name {
			delete(n.node.GetLinks(), name)
		}

		return nil
	})

}

func (m *Manager) GetLinks() map[string]*subscribe.Link {
	var links map[string]*subscribe.Link
	_ = m.db.View(func(n *Node) error {
		links = n.node.GetLinks()
		return nil
	})
	return links
}

func (m *Manager) UsePoint(tcp, udp bool, hash string) error {
	err := m.db.Batch(func(n *Node) error {
		p, ok := n.GetNode(hash)
		if !ok {
			return errors.New("node not found")
		}

		if tcp {
			n.node.SetTcp(p)
		}

		if udp {
			n.node.SetUdp(p)
		}

		return nil
	})
	if err == nil {
		m.clearIdleProxy()
	}
	return err
}

func (m *Manager) Save() error {
	return m.db.Save()
}

func (m *Manager) clearIdleProxy() {
	_ = m.db.View(func(n *Node) error {
		usedHash := n.GetUsingPoints()

		for k := range m.store.Range {
			if usedHash.Has(k) {
				m.store.Delete(k)
			}
		}

		return nil
	})

}

func (m *Manager) Close() error                                { return m.store.Close() }
func (m *Manager) Node() *Nodes                                { return &Nodes{manager: m} }
func (f *Manager) Subscribe() *Subscribe                       { return &Subscribe{n: f} }
func (n *Manager) Outbound() *outbound                         { return NewOutbound(n) }
func (n *Manager) Links() *link                                { return &link{n} }
func (f *Manager) Tag(ff func() iter.Seq[string]) gn.TagServer { return &tag{n: f, ruleTags: ff} }

type DB struct {
	db *jsondb.DB[*node.Node]
	mu sync.RWMutex
}

func (d *DB) Save() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.db.Save()
}

func (d *DB) View(f func(*Node) error) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return f(&Node{d.db.Data})
}

func (d *DB) Batch(f func(*Node) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return f(&Node{d.db.Data})
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

func (m *Node) GetNodeByName(group, name string) (*point.Point, bool) {
	z := m.GetManager().GetGroupsV2()[group]
	if z == nil {
		return nil, false
	}

	hash := z.GetNodesV2()[name]
	if hash == "" {
		return nil, false
	}

	return m.GetNode(hash)
}

func (m *Node) isNodeNameExists(group, name string) (string, bool) {
	groups := m.GetManager().GetGroupsV2()
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

	pp, ok = n.GetNodeByName(p.GetGroup(), p.GetName())
	if ok {
		return pp
	}

	return p
}

func (n *Node) GetUsingPoints() *list.Set[string] {
	set := list.NewSet[string]()

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
