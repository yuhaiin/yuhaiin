package node

import (
	"context"
	"sort"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func (m *Manager) SelectedContract(ctx context.Context) contractnode.Selection {
	tcp, tcpOK, _ := m.persist.GetContractNow(true)
	udp, udpOK, _ := m.persist.GetContractNow(false)
	var out contractnode.Selection
	if tcpOK {
		out.TCP = &tcp
	}
	if udpOK {
		out.UDP = &udp
	}
	return out
}

func (m *Manager) ActiveContract(ctx context.Context) []contractnode.Node {
	var items []contractnode.Node
	m.store.Range(func(key string, value *ProxyEntry) bool {
		if value == nil {
			return true
		}
		value.mu.RLock()
		defer value.mu.RUnlock()
		if value.ContractConfig != nil {
			items = append(items, *value.ContractConfig)
		}
		return true
	})
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func (m *Manager) SaveContract(ctx context.Context, in contractnode.Node) (contractnode.Node, error) {
	in.Origin = "manual"
	if err := m.persist.SaveContractNode(in); err != nil {
		return contractnode.Node{}, err
	}
	m.store.Delete(in.ID)
	return in, nil
}
