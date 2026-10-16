package lightweighttun

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"testing"
)

func TestConfiguration(t *testing.T) {
	for _, cc := range []string{"", "reno", "cubic", "bbr"} {
		if err := Validate(device.TunConfig{Stack: "lightweight", CongestionControl: cc}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []device.TunConfig{{Driver: device.DriverFDBased}, {Driver: device.DriverSystemGvisor}, {CongestionControl: "fake-bbr"}, {MTU: 900}} {
		if err := Validate(c); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}
