package vmess

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	gcvmess "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess/gitsrcvmess"
)

//Vmess vmess client
type Vmess struct {
	uuid     string
	security string
	alterID  uint32

	client  *gcvmess.Client
	getConn proxy.Proxy
}

func NewVmess(uuid, security string, alterID uint32) func(p proxy.Proxy) (proxy.Proxy, error) {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		client, err := gcvmess.NewClient(uuid, security, int(alterID), alterID == 0)
		if err != nil {
			return nil, fmt.Errorf("new vmess client failed: %v", err)
		}

		v := &Vmess{
			uuid:     uuid,
			security: security,
			alterID:  alterID,
			client:   client,
			getConn:  p,
		}

		return v, nil
	}

}

//Conn create a connection for host
func (v *Vmess) Conn(host string) (conn net.Conn, err error) {
	return v.conn("tcp", host)
}

//PacketConn packet transport connection
func (v *Vmess) PacketConn(host string) (conn net.PacketConn, err error) {
	return v.conn("udp", host)
}

func (v *Vmess) conn(network, host string) (*gcvmess.Conn, error) {
	conn, err := v.getConn.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %w", err)
	}
	rconn, err := v.client.NewConn(conn, network, host)
	if err != nil {
		return nil, fmt.Errorf("get vmess conn failed: %w", err)
	}
	return rconn, nil
}
