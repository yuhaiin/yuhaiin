//go:build linux && lightweight_kernel

package tun

import (
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"testing"
)

type reviewMTUHandler struct{}

func (reviewMTUHandler) HandlePing(*netapi.PingMeta)       {}
func (reviewMTUHandler) HandleStream(m *netapi.StreamMeta) { _ = m.Src.Close() }
func (reviewMTUHandler) HandlePacket(p *netapi.Packet)     { p.DecRef() }

// Run only in a fresh isolated user/network namespace with /dev/net/tun.
func TestLegacyIPv4MTU1200(t *testing.T) {
	old := configuration.IPv6.Load()
	configuration.IPv6.Store(false)
	t.Cleanup(func() { configuration.IPv6.Store(old) })
	s, err := NewTun(device.TunConfig{Name: "tun://reviewlow0", MTU: 1200, Driver: device.DriverChannel, Portal: "172.31.255.1/24"}, nil, reviewMTUHandler{})
	if err != nil {
		t.Fatalf("legacy IPv4 MTU=1200 cannot start: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
