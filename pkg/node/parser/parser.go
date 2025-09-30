package parser

import (
	"bytes"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

var store syncmap.SyncMap[subscribe.Type, func(data []byte) (*point.Point, error)]

func Parse(t subscribe.Type, data []byte) (*point.Point, error) {
	parser, ok := store.Load(t)
	if !ok {
		return nil, fmt.Errorf("no support %s", t)
	}

	return parser(data)
}

func ParseUrl(str []byte, l *subscribe.Link) (no *point.Point, err error) {
	var schemeTypeMap = map[string]subscribe.Type{
		"ss":     subscribe.Type_shadowsocks,
		"ssr":    subscribe.Type_shadowsocksr,
		"vmess":  subscribe.Type_vmess,
		"trojan": subscribe.Type_trojan,
	}

	t := l.GetType()

	if t == subscribe.Type_reserve {
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
