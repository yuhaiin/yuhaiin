package lightweight

import (
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"net/netip"
	"slices"
	"time"
)

type NetworkProfile string

const (
	LocalTun     NetworkProfile = "local_tun"
	RemoteTunnel NetworkProfile = "remote_tunnel"
)

type Config struct {
	OutputScheduler                                                               trafficcontrol.SchedulerMode
	Addresses                                                                     []netip.Addr
	MTU                                                                           int
	CongestionControl                                                             string
	Profile                                                                       NetworkProfile
	Promiscuous, ForwardUDP                                                       bool
	MaxConnections, MaxUDPSockets, QueuePackets                                   int
	InputPacketsPerSecond, InputPacketBurst                                       int
	SendBuffer, ReceiveBuffer, MaxReceiveBuffer                                   int
	MemoryLimit                                                                   int64
	MaxFragmentGroups, MaxFragmentBytes                                           int
	FragmentTimeout, HandshakeTimeout, TimeWait, KeepaliveIdle, KeepaliveInterval time.Duration
	KeepaliveProbes                                                               int

	// ForwardPing queues nonlocal Echo requests for ReceivePing instead of replying locally.
	// It is opt-in; VPN stacks and the production TUN adapter leave it disabled.
	ForwardPing bool
}

func (c Config) normalize() (Config, error) {
	if c.OutputScheduler == "" {
		c.OutputScheduler = trafficcontrol.SchedulerFIFO
	}
	if c.OutputScheduler != trafficcontrol.SchedulerFair && c.OutputScheduler != trafficcontrol.SchedulerFIFO {
		return c, fmt.Errorf("lightweight: unknown output scheduler %q", c.OutputScheduler)
	}
	if c.MTU == 0 {
		c.MTU = 1500
	}
	// IPv4 permits smaller links; IPv6 addresses are checked below.
	minMTU := 576
	if c.MTU < minMTU || c.MTU > 65535 {
		return c, fmt.Errorf("lightweight: MTU must be %d..65535", minMTU)
	}
	if c.CongestionControl == "" {
		c.CongestionControl = "cubic"
		if c.Profile == RemoteTunnel {
			c.CongestionControl = "bbr"
		}
	}
	if c.Profile == "" {
		c.Profile = LocalTun
	}
	if c.Profile != LocalTun && c.Profile != RemoteTunnel {
		return c, fmt.Errorf("lightweight: unknown profile %q", c.Profile)
	}
	if c.InputPacketsPerSecond < 0 || c.InputPacketBurst < 0 {
		return c, fmt.Errorf("lightweight: negative input packet rate limit")
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 8192
	}
	if c.MaxUDPSockets == 0 {
		c.MaxUDPSockets = 1024
	}
	if c.QueuePackets == 0 {
		c.QueuePackets = 1024
	}
	if c.SendBuffer == 0 {
		c.SendBuffer = 1 << 20
		if c.Profile == RemoteTunnel {
			c.SendBuffer = 6 << 20
		}
	}
	if c.ReceiveBuffer == 0 {
		c.ReceiveBuffer = 64 << 10
	}
	if c.Profile == RemoteTunnel && c.ReceiveBuffer == 64<<10 {
		c.ReceiveBuffer = 256 << 10
	}
	if c.MaxReceiveBuffer == 0 {
		c.MaxReceiveBuffer = 8 << 20
	}
	if c.MemoryLimit == 0 {
		c.MemoryLimit = 256 << 20
	}
	if c.MaxFragmentGroups == 0 {
		c.MaxFragmentGroups = 256
	}
	if c.MaxFragmentBytes == 0 {
		c.MaxFragmentBytes = 4 << 20
	}
	if c.FragmentTimeout == 0 {
		c.FragmentTimeout = 30 * time.Second
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 30 * time.Second
	}
	if c.TimeWait == 0 {
		c.TimeWait = 2 * time.Minute
	}
	if c.KeepaliveIdle < 0 || c.KeepaliveInterval < 0 {
		return c, fmt.Errorf("lightweight: negative keepalive duration")
	}
	if c.KeepaliveInterval == 0 {
		c.KeepaliveInterval = 30 * time.Second
	}
	if c.KeepaliveProbes == 0 {
		c.KeepaliveProbes = 9
	}
	if c.MaxConnections < 1 || c.MaxConnections > 1<<20 || c.MaxUDPSockets < 1 || c.MaxUDPSockets > 65535 || c.QueuePackets < 1 || c.QueuePackets > 65536 || c.SendBuffer < 4096 || c.SendBuffer > 1<<28 || c.ReceiveBuffer < 4096 || c.ReceiveBuffer > c.MaxReceiveBuffer || c.MaxReceiveBuffer > 1<<28 || c.MemoryLimit < 1<<20 || c.MaxFragmentGroups < 1 || c.MaxFragmentGroups > 65536 || c.MaxFragmentBytes < 65535 || c.MaxFragmentBytes > 1<<28 || c.FragmentTimeout < time.Millisecond || c.HandshakeTimeout < time.Millisecond || c.TimeWait < time.Millisecond || c.KeepaliveProbes < 1 || c.KeepaliveProbes > 100 {
		return c, fmt.Errorf("lightweight: invalid resource or timeout limits")
	}
	c.Addresses = slices.Clone(c.Addresses)
	for _, a := range c.Addresses {
		if a.Is6() && c.MTU < 1280 {
			return c, fmt.Errorf("lightweight: IPv6 requires MTU >= 1280")
		}
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() || a.Zone() != "" {
			return c, fmt.Errorf("lightweight: invalid local address %v", a)
		}
	}
	if _, err := congestion.New(c.CongestionControl, congestion.Config{MSS: uint64(c.MTU - 60), MaxWindow: uint64(c.SendBuffer)}); err != nil {
		return c, err
	}
	return c, nil
}

// ValidateConfig validates without taking ownership of any device.
func ValidateConfig(c Config) error { _, err := c.normalize(); return err }
