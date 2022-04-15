package node

import (
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

type manager struct {
	*node.Manager
	lock sync.RWMutex
}

func (m *manager) GetNode(hash string) (*node.Point, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	p, ok := m.Nodes[hash]
	return p, ok
}

func (m *manager) GetNodeByName(group, name string) (*node.Point, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	z := m.GroupNodesMap[group]
	if z == nil {
		return nil, false
	}

	hash := z.NodeHashMap[name]
	if hash != "" {
		return nil, false
	}

	return m.GetNode(hash)
}

func (m *manager) AddNode(p *node.Point) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.Nodes == nil {
		m.Nodes = make(map[string]*node.Point)
	}
	if m.GroupNodesMap == nil {
		m.GroupNodesMap = make(map[string]*node.ManagerNodeArray)
	}
	_, ok := m.GroupNodesMap[p.Group]
	if !ok {
		m.GroupNodesMap[p.Group] = &node.ManagerNodeArray{
			Group:       p.Group,
			Nodes:       make([]string, 0),
			NodeHashMap: make(map[string]string),
		}
		m.Groups = append(m.Groups, p.Group)
	}

	_, ok = m.GroupNodesMap[p.Group].NodeHashMap[p.Name]
	if !ok {
		m.GroupNodesMap[p.Group].Nodes = append(m.GroupNodesMap[p.Group].Nodes, p.Name)
	}
	m.GroupNodesMap[p.Group].NodeHashMap[p.Name] = p.Hash
	m.Nodes[p.Hash] = p
}

func (n *manager) DeleteRemoteNodes(group string) {
	n.lock.Lock()
	defer n.lock.Unlock()

	m := n.Manager

	x, ok := m.GroupNodesMap[group]
	if !ok {
		return
	}

	ns := x.Nodes
	msmap := x.NodeHashMap
	left := make([]string, 0)
	for i := range ns {
		if m.Nodes[msmap[ns[i]]].GetOrigin() != node.Point_remote {
			left = append(left, ns[i])
			continue
		}

		delete(m.Nodes, msmap[ns[i]])
		delete(m.GroupNodesMap[group].NodeHashMap, ns[i])
	}

	if len(left) == 0 {
		delete(m.GroupNodesMap, group)
		for i, x := range m.Groups {
			if x != group {
				continue
			}

			m.Groups = append(m.Groups[:i], m.Groups[i+1:]...)
			break
		}
		return
	}

	m.GroupNodesMap[group].Nodes = left
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
	delete(m.GroupNodesMap[p.Group].NodeHashMap, p.Name)

	for i, x := range m.GroupNodesMap[p.Group].Nodes {
		if x != p.Name {
			continue
		}

		m.GroupNodesMap[p.Group].Nodes = append(
			m.GroupNodesMap[p.Group].Nodes[:i],
			m.GroupNodesMap[p.Group].Nodes[i+1:]...,
		)
	}

	if len(m.GroupNodesMap[p.Group].Nodes) != 0 {
		return
	}

	delete(m.GroupNodesMap, p.Group)

	for i, x := range m.Groups {
		if x != p.Group {
			continue
		}

		m.Groups = append(m.Groups[:i], m.Groups[i+1:]...)
		break
	}
}
