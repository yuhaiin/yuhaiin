package store

import pn "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"

func defaultNodeData() *pn.Node {
	defaultNode := &pn.Node_builder{
		Tcp:   &pn.Point{},
		Udp:   &pn.Point{},
		Links: map[string]*pn.Link{},
		Manager: (&pn.Manager_builder{
			Nodes:     map[string]*pn.Point{},
			Tags:      map[string]*pn.Tags{},
			Publishes: map[string]*pn.Publish{},
		}).Build(),
	}

	defaultNode.Tcp.SetHash("inittcp")
	defaultNode.Udp.SetHash("initudp")

	return defaultNode.Build()
}

func normalizeNodeData(data *pn.Node) {
	if data.GetManager() == nil {
		data.SetManager(&pn.Manager{})
	}
	if data.GetManager().GetNodes() == nil {
		data.GetManager().SetNodes(make(map[string]*pn.Point))
	}
	if data.GetManager().GetTags() == nil {
		data.GetManager().SetTags(make(map[string]*pn.Tags))
	}
	if data.GetManager().GetPublishes() == nil {
		data.GetManager().SetPublishes(make(map[string]*pn.Publish))
	}
	if data.GetLinks() == nil {
		data.SetLinks(make(map[string]*pn.Link))
	}
	if data.GetTcp() == nil {
		data.SetTcp(&pn.Point{})
	}
	if data.GetUdp() == nil {
		data.SetUdp(&pn.Point{})
	}
}
