package node

import (
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
)

func load(path string) *jsondb.DB[*node.Node] {
	defaultNode := &node.Node{
		Tcp:   &point.Point{},
		Udp:   &point.Point{},
		Links: map[string]*subscribe.Link{},
		Manager: &node.Manager{
			GroupsV2: map[string]*node.Nodes{},
			Nodes:    map[string]*point.Point{},
			Tags:     map[string]*pt.Tags{},
		},
	}

	return jsondb.Open[*node.Node](path, defaultNode)
}

type FileStore struct {
	db       *jsondb.DB[*node.Node]
	manAger  *manager
	outBound *outbound
	links    *link
}

func NewFileStore(path string) *FileStore {
	f := &FileStore{
		db: load(path),
	}

	f.manAger = NewManager(f.db.Data.Manager)
	f.outBound = NewOutbound(f.db, f.manAger)
	f.links = NewLink(f.db, f.outBound, f.manAger)

	return f
}

func (f *FileStore) outbound() *outbound { return f.outBound }
func (f *FileStore) link() *link         { return f.links }
func (f *FileStore) manager() *manager   { return f.manAger }
func (n *FileStore) Save() error         { return n.db.Save() }
