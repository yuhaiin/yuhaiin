package macos

import (
	"encoding/json/v2"
	"fmt"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/legacy/chore"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
)

type TUNOptions struct {
	Portal   string
	PortalV6 string
	FD       int32
	MTU      int32
}

func NewFakeDB(tun TUNOptions, path string) chore.DB {
	settings := config.Setting_builder{
		Server: config.InboundConfig_builder{
			HijackDns: new(true),
			Sniff: config.Sniff_builder{
				Enabled: new(true),
			}.Build(),
			Inbounds: map[string]*config.Inbound{
				"mix": config.Inbound_builder{
					Name:    new("mix"),
					Enabled: new(false),
					Tcpudp: config.Tcpudp_builder{
						Host:    new("127.0.0.1:0"),
						Control: config.TcpUdpControl_tcp_udp_control_all.Enum(),
					}.Build(),
					Mix: &config.Mixed{},
				}.Build(),
				"tun": config.Inbound_builder{
					Name:    new("tun"),
					Enabled: new(true),
					Empty:   &config.Empty{},
					Tun: config.Tun_builder{
						Name:          new(fmt.Sprintf("fd://%d", tun.FD)),
						Mtu:           new(tun.MTU),
						Portal:        new(tun.Portal),
						PortalV6:      new(tun.PortalV6),
						SkipMulticast: new(true),
						Route:         &config.Route{},
						Driver:        config.Tun_system_gvisor.Enum(),
					}.Build(),
				}.Build(),
			},
		}.Build(),
		Dns:         &config.DnsConfig{},
		SystemProxy: &config.SystemProxy{},
		Bypass:      &config.BypassConfig{},
		Logcat:      &config.Logcat{},
		Platform:    config.Platform_builder{}.Build(),
	}.Build()

	return &fakeSettings{setting: settings, dir: filepath.Dir(path)}
}

type fakeSettings struct {
	setting *config.Setting
	dir     string
}

func (w *fakeSettings) View(f ...func(*config.Setting) error) error {
	for i := range f {
		if err := f[i](w.setting); err != nil {
			return err
		}
	}
	return nil
}

func (w *fakeSettings) Batch(f ...func(*config.Setting) error) error {
	config := cloneSetting(w.setting)
	for i := range f {
		if err := f[i](config); err != nil {
			return err
		}
	}
	return nil
}

func (w *fakeSettings) Dir() string { return w.dir }

func cloneSetting(src *config.Setting) *config.Setting {
	if src == nil {
		return nil
	}
	dst := &config.Setting{}
	if data, err := json.Marshal(src); err == nil {
		if err := json.Unmarshal(data, dst); err == nil {
			return dst
		}
	}
	return src
}
