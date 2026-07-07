package node

import (
	"errors"
	"iter"

	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

type Manager struct {
	persist NodeStore
	store   *ProxyStore
}

func NewManager(path string) *Manager {
	store := NewSqliteNodeStore(path)
	_, _ = store.Load()
	return &Manager{persist: store, store: NewProxyStore()}
}

func (m *Manager) Close() error {
	var err error
	if m.persist != nil {
		err = errors.Join(err, m.persist.Close())
	}
	return errors.Join(err, m.store.Close())
}
func (m *Manager) Node() *Nodes                                 { return &Nodes{manager: m} }
func (m *Manager) Subscribe() *Subscribe                        { return &Subscribe{n: m} }
func (m *Manager) Outbound() *Outbound                          { return &Outbound{manager: m} }
func (m *Manager) Tag(ff func() iter.Seq[string]) api.TagServer { return &tag{n: m, ruleTags: ff} }

func (m *Manager) Store() *ProxyStore { return m.store }

func (m *Manager) SaveNode(ps ...*node.Point) error {
	for _, p := range ps {
		if p.GetHash() != "" {
			m.store.Refresh(p)
		}
	}
	return m.persist.SaveNodes(ps...)
}

func (m *Manager) DeleteRemoteNodes(group string) error {
	if err := m.persist.DeleteRemoteNodes(group); err != nil {
		return err
	}
	return m.clearIdleProxy()
}

func (m *Manager) ReplaceRemoteNodes(group string, ps ...*node.Point) error {
	for _, p := range ps {
		if p.GetHash() != "" {
			m.store.Refresh(p)
		}
	}
	if err := m.persist.ReplaceRemoteNodes(group, ps...); err != nil {
		return err
	}
	return m.clearIdleProxy()
}

func (m *Manager) DeleteNode(hash string) error {
	m.store.Delete(hash)
	if err := m.persist.DeleteNode(hash); err != nil {
		return err
	}
	return m.clearIdleProxy()
}

func (m *Manager) AddTag(tag string, t node.TagType, hash string) error {
	if err := m.persist.AddTag(tag, t, hash); err != nil {
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

func (m *Manager) SaveLinks(links ...*node.Link) error {
	return m.persist.SaveLinks(links...)
}

func (m *Manager) DeleteLink(name ...string) error {
	return m.persist.DeleteLinks(name...)
}

func (m *Manager) UsePoint(hash string) error {
	if err := m.persist.UsePoint(hash); err != nil {
		return err
	}
	return m.clearIdleProxy()
}

func (m *Manager) clearIdleProxy() error {
	usedHash, err := m.persist.UsingPoints()
	if err != nil {
		return err
	}

	for k := range m.store.Range {
		if !usedHash.Has(k) {
			m.store.Delete(k)
		}
	}
	return nil
}

func (m *Manager) getUsingPoints() *set.Set[string] {
	used, err := m.persist.UsingPoints()
	if err != nil {
		return set.NewSet[string]()
	}
	return used
}

func (m *Manager) GetUsingPoints() *set.Set[string] {
	return m.getUsingPoints()
}

func (d *Manager) GetGroups() map[string][]*api.NodesResponse_Node {
	groups, err := d.persist.GetGroups()
	if err != nil {
		return map[string][]*api.NodesResponse_Node{}
	}
	return groups
}

func (d *Manager) GetNode(hash string) (*node.Point, bool) {
	p, ok, err := d.persist.GetNode(hash)
	if err != nil {
		return nil, false
	}
	return p, ok
}

func (d *Manager) GetNow(tcp bool) *node.Point {
	point, err := d.persist.GetNow(tcp)
	if err != nil {
		return &node.Point{}
	}
	return point
}

func (d *Manager) GetTag(tag string) (*node.Tags, bool) {
	t, ok, err := d.persist.GetTag(tag)
	if err != nil {
		return nil, false
	}
	return t, ok
}

func (d *Manager) GetTags() map[string]*node.Tags {
	tags, err := d.persist.GetTags()
	if err != nil {
		return map[string]*node.Tags{}
	}
	return tags
}

func (d *Manager) GetLinks() map[string]*node.Link {
	links, err := d.persist.GetLinks()
	if err != nil {
		return map[string]*node.Link{}
	}
	return links
}

func (d *Manager) GetLink(name string) (*node.Link, bool) {
	l, ok, err := d.persist.GetLink(name)
	if err != nil {
		return nil, false
	}
	return l, ok
}

func (d *Manager) Save() error {
	return nil
}

func (d *Manager) SavePublish(name string, publish *node.Publish) error {
	return d.persist.SavePublish(name, publish)
}

func (d *Manager) DeletePublish(name string) error {
	return d.persist.DeletePublish(name)
}

func (d *Manager) GetPublishes() map[string]*node.Publish {
	publishes, err := d.persist.GetPublishes()
	if err != nil {
		return map[string]*node.Publish{}
	}
	return publishes
}

func (d *Manager) Publish(name, path, password string) []*node.Point {
	points, err := d.persist.Publish(name, path, password)
	if err != nil {
		return nil
	}
	return points
}
