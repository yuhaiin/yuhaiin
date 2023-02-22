package node

import (
	"errors"
	"fmt"
	"os"
	"path"
	"sync"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"google.golang.org/protobuf/encoding/protojson"
)

func load(path string) *node.Node {
	defaultNode, _ := protojson.Marshal(&node.Node{
		Tcp:   &point.Point{},
		Udp:   &point.Point{},
		Links: map[string]*subscribe.Link{},
		Manager: &node.Manager{
			GroupsV2: map[string]*node.Nodes{},
			Nodes:    map[string]*point.Point{},
			Tags:     map[string]*pt.Tags{},
		},
	})

	data, err := os.ReadFile(path)
	if err != nil {
		log.Errorln("read node file failed:", err)
	}

	data = config.SetDefault(data, defaultNode)

	no := &node.Node{}
	if err = (protojson.UnmarshalOptions{DiscardUnknown: true, AllowPartial: true}).Unmarshal(data, no); err != nil {
		log.Errorln("unmarshal node file failed:", err)
	}

	return no
}

func (n *FileStore) toNode() *node.Node {
	return &node.Node{
		Tcp:     n.outBound.TCP,
		Udp:     n.outBound.UDP,
		Links:   n.links.Links(),
		Manager: n.manAger.GetManager(),
	}
}

type FileStore struct {
	mu   sync.RWMutex
	path string

	manAger  *manager
	outBound *outbound
	links    *link
}

func NewFileStore(path string) *FileStore {
	f := &FileStore{path: path}

	no := f.Load()

	f.manAger = NewManager(no.Manager)
	f.outBound = NewOutbound(no.Tcp, no.Udp, f.manAger)
	f.links = NewLink(f.outBound, f.manAger, no.Links)

	return f
}

func (f *FileStore) outbound() *outbound { return f.outBound }
func (f *FileStore) link() *link         { return f.links }
func (f *FileStore) manager() *manager   { return f.manAger }

func (n *FileStore) Load() *node.Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return load(n.path)
}

func (n *FileStore) Save() error {
	_, err := os.Stat(path.Dir(n.path))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}

		err = os.MkdirAll(path.Dir(n.path), os.ModePerm)
		if err != nil {
			return fmt.Errorf("make config dir failed: %w", err)
		}
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	dataBytes, err := protojson.MarshalOptions{Indent: "\t"}.Marshal(n.toNode())
	if err != nil {
		return fmt.Errorf("marshal file failed: %w", err)
	}

	return os.WriteFile(n.path, dataBytes, os.ModePerm)
}
