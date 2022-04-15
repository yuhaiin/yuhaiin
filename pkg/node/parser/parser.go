package parser

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var parseLink syncmap.SyncMap[node.NodeLinkLinkType, func(data []byte) (*node.Point, error)]

func ParseLinkData(t node.NodeLinkLinkType, data []byte) (*node.Point, error) {
	parser, ok := parseLink.Load(t)
	if !ok {
		return nil, fmt.Errorf("no support %s", t)
	}

	return parser(data)
}
