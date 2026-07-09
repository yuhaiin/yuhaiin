package device

import (
	"os/exec"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var Mark = 0x00000500

type Driver string

const (
	DriverFDBased      Driver = "fdbased"
	DriverChannel      Driver = "channel"
	DriverSystemGvisor Driver = "system_gvisor"
)

type TunConfig struct {
	Name          string         `json:"name,omitzero"`
	MTU           int32          `json:"mtu,omitzero"`
	ForceFakeIP   bool           `json:"force_fakeip,omitzero"`
	SkipMulticast bool           `json:"skip_multicast,omitzero"`
	Driver        Driver         `json:"driver,omitzero"`
	Portal        string         `json:"portal,omitzero"`
	PortalV6      string         `json:"portal_v6,omitzero"`
	Routes        []string       `json:"routes,omitzero"`
	PostUp        []string       `json:"post_up,omitzero"`
	PostDown      []string       `json:"post_down,omitzero"`
	Platform      PlatformConfig `json:"platform,omitzero"`
}

type PlatformConfig struct {
	Darwin DarwinConfig `json:"darwin,omitzero"`
}

type DarwinConfig struct {
	NetworkService string `json:"network_service,omitzero"`
}

type Opt struct {
	Tun TunConfig
	*netlink.Options
	netapi.Handler

	UnsetRoute func()
}

func (o *Opt) PostDown() {
	execPost(o.Tun.PostDown)
	o.UnSkipMark()
	if o.UnsetRoute != nil {
		o.UnsetRoute()
	}
}

func (o *Opt) PostUp() {
	execPost(o.Tun.PostUp)
	o.SkipMark()
}

func (o *Opt) InterfaceAddress() InterfaceAddress {
	return InterfaceAddress{
		Addressv4: tcpip.AddrFromSlice(o.V4Address().Addr().AsSlice()),
		Portalv4:  tcpip.AddrFromSlice(o.V4Address().Addr().Next().AsSlice()),
		AddressV6: tcpip.AddrFromSlice(o.V6Address().Addr().AsSlice()),
		PortalV6:  tcpip.AddrFromSlice(o.V6Address().Addr().Next().AsSlice()),
	}
}

type InterfaceAddress struct {
	Addressv4 tcpip.Address
	Portalv4  tcpip.Address
	AddressV6 tcpip.Address
	PortalV6  tcpip.Address
}

func (h InterfaceAddress) IsDNSRequest(port uint16, addr tcpip.Address) bool {
	if port != 53 {
		return false
	}

	return addr.Equal(h.Portalv4) || addr.Equal(h.PortalV6) ||
		(addr.Equal(h.Addressv4) || addr.Equal(h.AddressV6))
}

func execPost(cmd []string) {
	if len(cmd) == 0 {
		return
	}
	output, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		log.Error("execPost", "err", err)
		return
	}

	log.Info("execPost", "cmd", cmd, "output", string(output))
}
