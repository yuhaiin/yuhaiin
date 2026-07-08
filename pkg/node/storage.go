package node

import (
	"github.com/Asutorufa/yuhaiin/pkg/schema/api"
	pn "github.com/Asutorufa/yuhaiin/pkg/schema/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

type NodeStore interface {
	Load() (*pn.Node, error)
	Save(*pn.Node) error

	SaveNodes(...*pn.Point) error
	DeleteRemoteNodes(group string) error
	ReplaceRemoteNodes(group string, points ...*pn.Point) error
	DeleteNode(hash string) error
	GetNode(hash string) (*pn.Point, bool, error)
	GetNow(tcp bool) (*pn.Point, error)
	UsePoint(hash string) error
	GetGroups() (map[string][]*api.NodesResponse_Node, error)

	AddTag(tag string, typ pn.TagType, hash string) error
	DeleteTag(tag string) error
	GetTag(tag string) (*pn.Tags, bool, error)
	GetTags() (map[string]*pn.Tags, error)
	UsingPoints() (*set.Set[string], error)

	SaveLinks(...*pn.Link) error
	DeleteLinks(...string) error
	GetLinks() (map[string]*pn.Link, error)
	GetLink(name string) (*pn.Link, bool, error)

	SavePublish(name string, publish *pn.Publish) error
	DeletePublish(name string) error
	GetPublishes() (map[string]*pn.Publish, error)
	Publish(name, path, password string) ([]*pn.Point, error)

	Close() error
}

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
