package android

import (
	"encoding/json/v2"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/legacy/chore"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
)

type RuntimeOptions struct {
	AllowLAN  bool
	HTTPPort  int32
	HijackDNS bool
	Sniff     bool
	TunDriver string
	TUN       TUNOptions
}

type TUNOptions struct {
	Portal   string
	PortalV6 string
	FD       int32
	MTU      int32
}

type RuntimeOptionsFunc func() RuntimeOptions

type inboundDB struct {
	base    chore.DB
	options RuntimeOptionsFunc
}

func NewInboundDB(base chore.DB, options RuntimeOptionsFunc) chore.DB {
	return &inboundDB{base: base, options: options}
}

func (a *inboundDB) View(f ...func(*config.Setting) error) error {
	return a.base.View(func(s *config.Setting) error {
		working := cloneSetting(s)
		a.applyRuntimeOverlay(working.GetServer())

		for _, fn := range f {
			if err := fn(working); err != nil {
				return err
			}
		}

		return nil
	})
}

func (a *inboundDB) Batch(f ...func(*config.Setting) error) error {
	return a.base.Batch(func(s *config.Setting) error {
		working := cloneSetting(s)
		a.applyRuntimeOverlay(working.GetServer())

		for _, fn := range f {
			if err := fn(working); err != nil {
				return err
			}
		}

		s.GetServer().SetHijackDns(working.GetServer().GetHijackDns())
		s.GetServer().SetHijackDnsFakeip(working.GetServer().GetHijackDnsFakeip())
		s.GetServer().SetSniff(working.GetServer().GetSniff())
		return nil
	})
}

func (a *inboundDB) Dir() string { return a.base.Dir() }

func (a *inboundDB) applyRuntimeOverlay(server *config.InboundConfig) {
	if server == nil {
		return
	}

	options := RuntimeOptions{}
	if a.options != nil {
		options = a.options()
	}

	listenHost := "127.0.0.1"
	if options.AllowLAN {
		listenHost = "0.0.0.0"
	}

	inbounds := map[string]*config.Inbound{
		"mix": config.Inbound_builder{
			Name:    new("mix"),
			Enabled: new(options.HTTPPort != 0),
			Tcpudp: config.Tcpudp_builder{
				Host:    new(net.JoinHostPort(listenHost, fmt.Sprint(options.HTTPPort))),
				Control: config.TcpUdpControl_tcp_udp_control_all.Enum(),
			}.Build(),
			Mix: &config.Mixed{},
		}.Build(),
		"tun": config.Inbound_builder{
			Name:    new("tun"),
			Enabled: new(true),
			Empty:   &config.Empty{},
			Tun: config.Tun_builder{
				Name:          new(fmt.Sprintf("fd://%d", options.TUN.FD)),
				Mtu:           new(options.TUN.MTU),
				Portal:        new(options.TUN.Portal),
				PortalV6:      new(options.TUN.PortalV6),
				SkipMulticast: new(true),
				Route:         &config.Route{},
				Driver:        config.TunEndpointDriver(config.TunEndpointDriver_value[options.TunDriver]).Enum(),
			}.Build(),
		}.Build(),
	}

	server.SetInbounds(inbounds)
	applyRuntimeSettings(options, server)
}

func applyRuntimeSettings(options RuntimeOptions, server *config.InboundConfig) {
	if server == nil {
		return
	}

	server.SetHijackDns(options.HijackDNS)
	server.SetHijackDnsFakeip(options.HijackDNS)

	sniff := server.GetSniff()
	if sniff == nil {
		sniff = &config.Sniff{}
	}
	sniff.SetEnabled(options.Sniff)
	server.SetSniff(sniff)
}

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
