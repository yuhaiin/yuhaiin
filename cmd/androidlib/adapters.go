package main

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	core "github.com/Asutorufa/yuhaiin/cmd/android"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
)

// coreActive is true from the start of core.start until core.stop returns.
// Platform callbacks that would act on a stopped core (socket protection,
// network binding, uid lookups, new VPN interfaces) return their neutral
// answer instead of reaching Kotlin, so a late callback of a previous core
// can not touch the next one.
var coreActive atomic.Bool

var errCoreStopped = errors.New("core is not running")

// sockets implements SocketProtect and SocketBind on top of the host.
type sockets struct{}

func (sockets) Protect(fd int32) bool {
	h := getHost()
	if h == nil || !coreActive.Load() {
		return true // nothing to bypass without a VPN
	}
	return h.Protect(fd)
}

func (sockets) Bind(fd int32, iface string) int64 {
	h := getHost()
	if h == nil || !coreActive.Load() {
		return 0
	}
	return h.Bind(fd, iface)
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

// uidDumper implements the process lookup.
type uidDumper struct{}

func (uidDumper) DumpUid(proto int32, srcIP string, srcPort int32, dstIP string, dstPort int32) (int32, error) {
	h := getHost()
	if h == nil || !coreActive.Load() {
		return 0, nil
	}
	return h.DumpUID(proto, srcIP, srcPort, dstIP, dstPort)
}

func (uidDumper) GetUidInfo(uid int32) (string, error) {
	data, err := hostCall("uid.name", []byte(`{"uid":`+strconv.FormatInt(int64(uid), 10)+`}`))
	return string(data), err
}

// vpnProvider implements VpnProvider.
type vpnProvider struct{}

func (vpnProvider) Establish(generation int64, config string) (int32, error) {
	h := getHost()
	if h == nil {
		return -1, errNoHost
	}
	if !coreActive.Load() {
		return -1, errCoreStopped
	}
	return h.Establish(generation, config)
}

func (vpnProvider) Release(generation int64) {
	// Always forwarded: a stopped core must still free its descriptors.
	if _, err := hostCall("vpn.release", []byte(`{"generation":`+strconv.FormatInt(generation, 10)+`}`)); err != nil && !errors.Is(err, errNoHost) {
		logWarn("vpn.release failed", err)
	}
}

func (vpnProvider) Authorization() string {
	data, err := hostCall("vpn.authorization", nil)
	if err != nil {
		return ""
	}
	return string(data)
}

func (vpnProvider) StatusChanged(status string) {
	if !coreActive.Load() {
		return
	}
	// Must not block the core: the host handler only publishes the value.
	if _, err := hostCall("vpn.status_changed", []byte(status)); err != nil && !errors.Is(err, errNoHost) {
		logWarn("vpn.status_changed failed", err)
	}
}

// appCatalog implements AppCatalog and AppIconProvider.
type appCatalog struct{}

func (appCatalog) InstalledApps() (string, error) {
	data, err := hostCall("apps.list", nil)
	return string(data), err
}

func (appCatalog) AppIcon(packageName string) ([]byte, error) {
	req, _ := json.Marshal(struct {
		Package string `json:"package"`
	}{packageName})
	return hostCall("apps.icon", req)
}

// platformActions implements PlatformActions.
type platformActions struct{}

func (platformActions) RestoreConfig(path string) error {
	req, _ := json.Marshal(struct {
		Path string `json:"path"`
	}{path})
	_, err := hostCall("platform.restore_config", req)
	return err
}

func (platformActions) RestartCore() error {
	_, err := hostCall("platform.restart_core", nil)
	return err
}

func (platformActions) PrivacyState() string { return hostString("platform.privacy_state") }

func (platformActions) WithdrawConsent() error {
	_, err := hostCall("platform.withdraw_consent", nil)
	return err
}

func (platformActions) UpdateState() string { return hostString("platform.update_state") }

func (platformActions) UpdateAction(action, arg string) error {
	req, _ := json.Marshal(struct {
		Action string `json:"action"`
		Arg    string `json:"arg"`
	}{action, arg})
	_, err := hostCall("platform.update_action", req)
	return err
}

func (platformActions) AppInfo() string { return hostString("platform.app_info") }

func hostString(op string) string {
	data, err := hostCall(op, nil)
	if err != nil {
		logWarn(op+" failed", err)
		return ""
	}
	return string(data)
}

// interfaces implements Interfaces: the host lists the device's network
// interfaces as JSON.
type interfaces struct{}

type ifaceJSON struct {
	Name              string `json:"name"`
	DisplayName       string `json:"displayName"`
	HardwareAddr      []byte `json:"hardwareAddr"`
	Index             int32  `json:"index"`
	MTU               int32  `json:"mtu"`
	IsUp              bool   `json:"isUp"`
	IsLoopback        bool   `json:"isLoopback"`
	IsPointToPoint    bool   `json:"isPointToPoint"`
	Broadcast         bool   `json:"broadcast"`
	SupportsMulticast bool   `json:"supportsMulticast"`
	IsVirtual         bool   `json:"isVirtual"`
	Addresses         []struct {
		Address   string `json:"address"`
		Broadcast string `json:"broadcast"`
		Mask      int32  `json:"mask"`
	} `json:"addresses"`
}

func (interfaces) GetInterfaces() (core.InterfaceIter, error) {
	data, err := hostCall("interfaces.list", nil)
	if err != nil {
		return nil, err
	}
	var list []ifaceJSON
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	it := &ifaceIter{}
	for _, in := range list {
		addrs := &addrIter{}
		for _, a := range in.Addresses {
			addrs.items = append(addrs.items, &core.AddressPrefix{Address: a.Address, Broadcast: a.Broadcast, Mask: a.Mask})
		}
		it.items = append(it.items, &core.Interface{
			Address: addrs, Name: in.Name, DisplayName: in.DisplayName, HardwareAddr: in.HardwareAddr,
			Index: in.Index, Mtu: in.MTU, IsUp: in.IsUp, IsLoopback: in.IsLoopback,
			IsPointToPoint: in.IsPointToPoint, Broadcast: in.Broadcast,
			SupportsMulticast: in.SupportsMulticast, IsVirtual: in.IsVirtual,
		})
	}
	return it, nil
}

type ifaceIter struct {
	items []*core.Interface
	pos   int
}

func (i *ifaceIter) HasNext() bool { return i.pos < len(i.items) }
func (i *ifaceIter) Reset()        { i.pos = 0 }
func (i *ifaceIter) Next() *core.Interface {
	if !i.HasNext() {
		return nil
	}
	i.pos++
	return i.items[i.pos-1]
}

type addrIter struct {
	items []*core.AddressPrefix
	pos   int
}

func (i *addrIter) HasNext() bool { return i.pos < len(i.items) }
func (i *addrIter) Reset()        { i.pos = 0 }
func (i *addrIter) Next() *core.AddressPrefix {
	if !i.HasNext() {
		return nil
	}
	i.pos++
	return i.items[i.pos-1]
}

type networkIter struct {
	items []*core.UnderlyingNetwork
	pos   int
}

func (i *networkIter) HasNext() bool { return i.pos < len(i.items) }
func (i *networkIter) Next() *core.UnderlyingNetwork {
	if !i.HasNext() {
		return nil
	}
	i.pos++
	return i.items[i.pos-1]
}

// installPlatform registers the host-backed adapters with the core package.
func installPlatform() {
	core.SetInterfaces(interfaces{})
	netlink.AltListRoutes = listRoutes
	core.SetProcessDumper(uidDumper{})
	core.SetVpnProvider(vpnProvider{})
	core.SetAppCatalog(appCatalog{})
	core.SetAppIconProvider(appCatalog{})
	core.SetPlatformActions(platformActions{})
}

// routeJSON is one route of an Android network's LinkProperties.
type routeJSON struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Type        string `json:"type"`
	OwnVPN      bool   `json:"ownVpn"`
}

// listRoutes asks the app for the routes Android reports for each network.
// Apps may not read the kernel routing table, so policy rules and tables are
// not available. An app without "routes.list" reports an error.
func listRoutes() ([]netlink.RouteEntry, error) {
	data, err := hostCall("routes.list", nil)
	if err != nil {
		return nil, err
	}
	var list []routeJSON
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	out := make([]netlink.RouteEntry, 0, len(list))
	for _, r := range list {
		dst, err := netip.ParsePrefix(strings.TrimSpace(r.Destination))
		if err != nil {
			continue
		}
		e := netlink.RouteEntry{Destination: dst.Masked(), Interface: r.Interface, Type: r.Type, OwnVPN: r.OwnVPN}
		if gw, err := netip.ParseAddr(strings.TrimSpace(r.Gateway)); err == nil && !gw.IsUnspecified() {
			e.Gateway = gw.Unmap()
		}
		out = append(out, e)
	}
	return out, nil
}
