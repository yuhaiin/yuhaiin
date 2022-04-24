package obfs

import (
	"fmt"
	"net"
	"strings"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
)

type creator func(net.Conn, ssr.ObfsInfo) IObfs

var (
	creatorMap = make(map[string]creator)
)

type IObfs interface {
	GetOverhead() int

	net.Conn
}

func register(name string, c creator) {
	creatorMap[name] = c
}

type Obfs struct {
	name     string
	info     ssr.ObfsInfo
	overhead int
	creator  creator
}

// NewObfs create an obfs object by name and return as an IObfs interface
func NewObfs(name string, info ssr.ObfsInfo) (*Obfs, error) {
	o, ok := creatorMap[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("obfs %s not found", name)
	}

	overhead := o(nil, info).GetOverhead()
	return &Obfs{name, info, overhead, o}, nil
}

func (o *Obfs) Overhead() int {
	return o.overhead
}

func (o *Obfs) Stream(conn net.Conn) net.Conn {
	return o.creator(conn, o.info)
}
