package lightweighttun

import (
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"testing"
)

func TestConfiguration(t *testing.T) {
	for _, cc := range []string{"", "reno", "cubic", "bbr"} {
		if err := Validate(device.TunConfig{Stack: "lightweight", CongestionControl: cc}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []device.TunConfig{{Driver: device.DriverFDBased}, {Driver: device.DriverSystemGvisor}, {CongestionControl: "fake-bbr"}, {MTU: 575}, {OutputScheduler: "invalid"}} {
		if err := Validate(c); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func TestOutputSchedulerSelection(t *testing.T) {
	for _, mode := range []string{"", "fifo", "fq_codel"} {
		if err := Validate(device.TunConfig{Stack: "lightweight", OutputScheduler: mode}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConfigurationIPv4SmallMTU(t *testing.T) {
	old := configuration.IPv6.Load()
	t.Cleanup(func() { configuration.IPv6.Store(old) })
	config := device.TunConfig{MTU: 1200, Portal: "192.0.2.1/24", PortalV6: "fd00::1/64"}
	configuration.IPv6.Store(false)
	if err := Validate(config); err != nil {
		t.Fatalf("IPv4-only legacy configuration: %v", err)
	}
	configuration.IPv6.Store(true)
	if err := Validate(config); err == nil {
		t.Fatal("IPv6 accepted MTU below 1280")
	}
}
