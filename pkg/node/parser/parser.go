package parser

import (
	"bytes"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

var store syncmap.SyncMap[node.Type, func(data []byte) (*node.Point, error)]

func Parse(t node.Type, data []byte) (*node.Point, error) {
	parser, ok := store.Load(t)
	if !ok {
		return nil, fmt.Errorf("no support %s", t)
	}

	return parser(data)
}

func ParseUrl(str []byte, l *node.Link) (no *node.Point, err error) {
	var schemeTypeMap = map[string]node.Type{
		"ss":     node.Type_shadowsocks,
		"ssr":    node.Type_shadowsocksr,
		"vmess":  node.Type_vmess,
		"trojan": node.Type_trojan,
	}

	t := l.GetType()

	if t == node.Type_reserve {
		scheme, _, _ := system.GetScheme(string(str))
		t = schemeTypeMap[scheme]
	}

	no, err = Parse(t, str)
	if err != nil {
		return nil, fmt.Errorf("parse link data failed: %w", err)
	}
	no.SetGroup(l.GetName())
	return no, nil
}

func trimJSON(b []byte, start, end byte) []byte {
	s := bytes.IndexByte(b, start)
	e := bytes.LastIndexByte(b, end)
	if s == -1 || e == -1 {
		return b
	}
	return b[s : e+1]
}
