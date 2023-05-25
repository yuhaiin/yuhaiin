package tun2socket

import (
	"io"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket/nat"
	"github.com/Asutorufa/yuhaiin/pkg/utils/goos"
)

type Tun2Socket struct {
	device io.Closer
	tcp    *nat.TCP
	udp    *nat.UDPv2
}

// noinspection GoUnusedExportedFunction
func StartTun2SocketGvisor(device io.ReadWriteCloser, gateway, portal netip.Addr, mtu int32) (*Tun2Socket, error) {
	tcp, udp, err := nat.StartGvisor(device, gateway, portal, mtu)
	if err != nil {
		return nil, err
	}

	return &Tun2Socket{device, tcp, udp}, nil
}

func (t *Tun2Socket) Close() error {
	_ = t.tcp.Close()
	_ = t.udp.Close()

	if goos.IsAndroid == 0 {
		return t.device.Close()
	}

	return nil
}

func (t *Tun2Socket) TCP() *nat.TCP   { return t.tcp }
func (t *Tun2Socket) UDP() *nat.UDPv2 { return t.udp }
