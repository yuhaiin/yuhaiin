package parser

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var store syncmap.SyncMap[node.NodeLinkLinkType, func(data []byte) (*node.Point, error)]

func Parse(t node.NodeLinkLinkType, data []byte) (*node.Point, error) {
	parser, ok := store.Load(t)
	if !ok {
		return nil, fmt.Errorf("no support %s", t)
	}

	return parser(data)
}
