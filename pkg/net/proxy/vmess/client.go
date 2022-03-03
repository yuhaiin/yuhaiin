package vmess

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	gcvmess "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess/gitsrcvmess"
)

//Vmess vmess client
type Vmess struct {
	client *gcvmess.Client
	dial   proxy.Proxy
}

func NewVmess(uuid, security string, alterID uint32) func(p proxy.Proxy) (proxy.Proxy, error) {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		client, err := gcvmess.NewClient(uuid, security, int(alterID))
		if err != nil {
			return nil, fmt.Errorf("new vmess client failed: %v", err)
		}

		return &Vmess{client: client, dial: p}, nil
	}

}

//Conn create a connection for host
func (v *Vmess) Conn(host string) (conn net.Conn, err error) {
	c, err := v.dial.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %w", err)
	}
	return v.client.NewConn(c, host)
}

//PacketConn packet transport connection
func (v *Vmess) PacketConn(host string) (conn net.PacketConn, err error) {
	c, err := v.dial.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %w", err)
	}
	return v.client.NewPacketConn(c, host)
}
