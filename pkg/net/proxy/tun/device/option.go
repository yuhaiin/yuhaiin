package device

import (
	"net/netip"
	"os/exec"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
)

var Mark = 0x00000500

type Driver string

const (
	DriverFDBased      Driver = "fdbased"
	DriverChannel      Driver = "channel"
	DriverSystemGvisor Driver = "system_gvisor"
)

type TunConfig struct {
	OutputScheduler   string          `json:"output_scheduler,omitzero"`
	Stack             string          `json:"stack,omitzero"`
	CongestionControl string          `json:"congestion_control,omitzero"`
	AutoFakeIPRoute   bool            `json:"auto_fakeip_route,omitzero"`
	FakeIPRanges      [2]netip.Prefix `json:"-"`
	Name              string          `json:"name,omitzero"`
	MTU               int32           `json:"mtu,omitzero"`
	ForceFakeIP       bool            `json:"force_fakeip,omitzero"`
	SkipMulticast     bool            `json:"skip_multicast,omitzero"`
	Driver            Driver          `json:"driver,omitzero"`
	Portal            string          `json:"portal,omitzero"`
	PortalV6          string          `json:"portal_v6,omitzero"`
	Routes            []string        `json:"routes,omitzero"`
	PostUp            []string        `json:"post_up,omitzero"`
	PostDown          []string        `json:"post_down,omitzero"`
	Platform          PlatformConfig  `json:"platform,omitzero"`
}

type PlatformConfig struct {
	Darwin DarwinConfig `json:"darwin,omitzero"`
}

type DarwinConfig struct {
	NetworkService    string `json:"network_service,omitzero"`
	ExperimentalBatch bool   `json:"experimental_batch,omitzero"`
	BatchSize         int    `json:"batch_size,omitzero"`
	PendingPackets    int    `json:"pending_packets,omitzero"`
}

var configureDarwinTUN = func(d netlink.Tun, _ bool, _ DarwinConfig) netlink.Tun { return d }

// ConfigureDarwinTUN applies per-inbound options after the native device opens.
// On other platforms this leaves the native device and its behavior unchanged.
func ConfigureDarwinTUN(d netlink.Tun, sc netlink.TunScheme, config DarwinConfig) netlink.Tun {
	return configureDarwinTUN(d, sc.Scheme == "tun", config)
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
