package parser

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var store syncmap.SyncMap[subscribe.Type, func(data []byte) (*point.Point, error)]

func Parse(t subscribe.Type, data []byte) (*point.Point, error) {
	parser, ok := store.Load(t)
	if !ok {
		return nil, fmt.Errorf("no support %s", t)
	}

	return parser(data)
}
