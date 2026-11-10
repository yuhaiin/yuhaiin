package yuhaiin

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/platformvpn"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

// VpnProvider is implemented by the Android background process. The core
// calls it when the TUN inbound starts, stops or must be rebuilt; it never
// receives packets.
//
// Ownership: Establish returns the descriptor of a ParcelFileDescriptor that
// Android keeps until Release(generation). Go duplicates it and closes only
// its duplicate. Release must be idempotent and ignore unknown generations.
type VpnProvider interface {
	// Establish builds a VpnService interface from config (platformvpn.Config
	// JSON). Errors are reported as "<code>: <message>" where code is
	// permission_required, consent_required or provider_unavailable.
	Establish(generation int64, config string) (int32, error)
	Release(generation int64)
	// Authorization reports {"prepared","consent","alwaysOn","lockdown"} JSON.
	Authorization() string
	// StatusChanged receives platform VPN status JSON. It must not block.
	StatusChanged(status string)
}

type providerAdapter struct{ p VpnProvider }

func (a providerAdapter) Establish(_ context.Context, generation uint64, config platformvpn.Config) (int, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return -1, err
	}
	fd, err := a.p.Establish(int64(generation), string(data))
	return int(fd), err
}

func (a providerAdapter) Release(generation uint64) { a.p.Release(int64(generation)) }

var (
	vpnProviderMu    sync.Mutex
	vpnProvider      VpnProvider
	vpnStatusCancel  func()
	activeAppMu      sync.Mutex
	activeApp        *App
	androidMTUPolicy = func() int32 { return androidVPNMTU(GetStore().GetString(AdvVPNMTUProfileKey)) }
)

func init() {
	platformvpn.Default.DefaultMTU = func() int32 { return androidMTUPolicy() }
	platformvpn.Default.Addresses = func() (netip.Prefix, netip.Prefix, error) {
		addr, err := GetTunAddress()
		if err != nil {
			return netip.Prefix{}, netip.Prefix{}, err
		}
		v4, err := netip.ParseAddr(addr.IPv4Address)
		if err != nil {
			return netip.Prefix{}, netip.Prefix{}, err
		}
		v6, err := netip.ParseAddr(addr.IPv6Address)
		if err != nil {
			return netip.Prefix{}, netip.Prefix{}, err
		}
		return netip.PrefixFrom(v4, 24), netip.PrefixFrom(v6, 64), nil
	}
}

func androidVPNMTU(profile string) int32 {
	switch profile {
	case VPNMTU1500Value:
		return 1500
	default:
		return 9000
	}
}

// SetVpnProvider registers the Android VPN adapter. It is process-wide and
// may be called before or after App.Start; nil unregisters it.
func SetVpnProvider(p VpnProvider) {
	vpnProviderMu.Lock()
	defer vpnProviderMu.Unlock()
	if vpnStatusCancel != nil {
		vpnStatusCancel()
		vpnStatusCancel = nil
	}
	vpnProvider = p
	if p == nil {
		platformvpn.Default.SetProvider(nil)
		return
	}
	platformvpn.Default.SetProvider(providerAdapter{p})
	vpnStatusCancel = platformvpn.Default.Subscribe(func(s platformvpn.Status) {
		data, err := json.Marshal(s)
		if err == nil {
			p.StatusChanged(string(data))
		}
	})
}

func currentVpnProvider() VpnProvider {
	vpnProviderMu.Lock()
	defer vpnProviderMu.Unlock()
	return vpnProvider
}

// VpnStatus returns the platform VPN runtime status JSON.
func VpnStatus() string {
	data, _ := json.Marshal(platformvpn.Default.Status())
	return string(data)
}

// NotifyVpnRevoked stops the VPN generation revoked by Android and records the
// user's choice by disabling the TUN inbound. Stale generations are ignored.
func NotifyVpnRevoked(generation int64) bool {
	if generation <= 0 || !platformvpn.Default.Revoked(uint64(generation)) {
		return false
	}
	activeAppMu.Lock()
	app := activeApp
	activeAppMu.Unlock()
	if app != nil {
		go func() {
			if err := app.setVpnEnabled(false, false); err != nil {
				log.Warn("disable TUN inbound after VPN revoke failed", "err", err)
			}
		}()
	}
	return true
}

// RequestVpnReconfigure rebuilds the active VPN after an Android-side
// preference (per-app VPN, route profile, ...) changed.
func RequestVpnReconfigure() { platformvpn.Default.RequestReconfigure() }

type vpnAuthorization struct {
	Prepared bool `json:"prepared"`
	Consent  bool `json:"consent"`
	AlwaysOn bool `json:"alwaysOn"`
	Lockdown bool `json:"lockdown"`
}

func currentAuthorization() (vpnAuthorization, bool) {
	p := currentVpnProvider()
	if p == nil {
		return vpnAuthorization{}, false
	}
	var auth vpnAuthorization
	if err := json.Unmarshal([]byte(p.Authorization()), &auth); err != nil {
		return vpnAuthorization{}, false
	}
	return auth, true
}

// androidTunID identifies the Android VPN TUN inbound in the inbound store.
const androidTunID = "tun"

func findAndroidTun(inbounds []contractinbound.Inbound) (contractinbound.Inbound, bool) {
	var legacy *contractinbound.Inbound
	for i := range inbounds {
		in := inbounds[i]
		if in.Protocol.Type != contractinbound.ProtocolTun || in.Protocol.Tun == nil {
			continue
		}
		if platformvpn.IsDevice(in.Protocol.Tun.Name) {
			return in, true
		}
		if legacy == nil {
			legacy = &inbounds[i]
		}
	}
	if legacy != nil {
		return *legacy, true
	}
	return contractinbound.Inbound{}, false
}

func androidTunProtocol(base contractinbound.TunProtocol) contractinbound.TunProtocol {
	store := GetStore()
	base.Name = platformvpn.DeviceName
	base.Stack = "lightweight"
	base.Driver = TunDriverChannelValue
	base.SkipMulticast = true
	if base.CongestionControl == "" {
		base.CongestionControl = store.GetString(AdvTunCongestionControlKey)
	}
	if base.OutputScheduler == "" {
		base.OutputScheduler = store.GetString(AdvTunOutputSchedulerKey)
	}
	if base.LossRecovery == "" {
		base.LossRecovery = store.GetString(AdvTunLossRecoveryKey)
	}
	return base
}

// ensureAndroidTUNInbound prepares the on-demand TUN inbound before the
// runtime starts. It replaces the v1 behaviour that rewrote the inbound to
// "fd://<n>" and force-enabled it on every VPN start.
//
//   - No TUN inbound: create a disabled platform inbound.
//   - Legacy "fd://" inbound (v1) or the seeded desktop "tun://" inbound:
//     convert it to the platform device once, disabled, so upgrading never
//     connects a VPN by itself. Addresses and MTU return to automatic values
//     because v1 regenerated them per connection.
//   - Platform inbound: keep the user's configuration unchanged.
//
// A v1 APK installed over this data rewrites the inbound again on its next
// VPN start, so this migration is rollback safe.
func ensureAndroidTUNInbound(ctx context.Context, db *sql.DB) error {
	store := plainstore.NewInboundStore(db)
	inbounds, err := store.List(ctx)
	if err != nil {
		return err
	}
	current, ok := findAndroidTun(inbounds)
	switch {
	case !ok:
		return store.Save(ctx, contractinbound.Inbound{
			ID:       androidTunID,
			Name:     "Android VPN",
			Enabled:  false,
			Network:  contractinbound.NewTypedNetwork(contractinbound.EmptyNetwork{}),
			Protocol: contractinbound.NewTypedProtocol(androidTunProtocol(contractinbound.TunProtocol{AutoFakeIPRoute: true})),
		}, 0)
	case platformvpn.IsDevice(current.Protocol.Tun.Name):
		return nil
	default:
		// v1 rewrote the whole protocol on every start, and the seeded
		// desktop "tun://tun0" inbound cannot run on Android, so neither
		// carries routes or addresses worth keeping.
		legacy := *current.Protocol.Tun
		legacy.Portal, legacy.PortalV6, legacy.MTU = "", "", 0
		legacy.Routes, legacy.Excludes, legacy.PostUp, legacy.PostDown = nil, nil, nil, nil
		legacy.AutoFakeIPRoute = true
		current.Enabled = false
		log.Info("migrated legacy Android TUN inbound to the on-demand platform device", "id", current.ID, "name", current.Protocol.Tun.Name)
		current.Protocol = contractinbound.NewTypedProtocol(androidTunProtocol(legacy))
		return store.Save(ctx, current, 0)
	}
}

// VpnEnabled reports the configured (desired) state of the Android VPN.
func (a *App) VpnEnabled() bool {
	cfg, err := a.androidTun()
	return err == nil && cfg.Enabled
}

// SetVpnEnabled turns the Android VPN on or off by enabling the TUN inbound.
// The core keeps running either way. Callers must have completed the VPN
// consent and VpnService.prepare flow before enabling.
func (a *App) SetVpnEnabled(enabled bool) error { return a.setVpnEnabled(enabled, true) }

func (a *App) androidTun() (contractinbound.Inbound, error) {
	contracts := a.contractStore()
	if contracts == nil {
		return contractinbound.Inbound{}, errors.New("yuhaiin is not running")
	}
	list, err := contracts.List(context.Background())
	if err != nil {
		return contractinbound.Inbound{}, err
	}
	cfg, ok := findAndroidTun(list)
	if !ok || !platformvpn.IsDevice(cfg.Protocol.Tun.Name) {
		return contractinbound.Inbound{}, errors.New("android TUN inbound is missing")
	}
	return cfg, nil
}

func (a *App) setVpnEnabled(enabled, retry bool) error {
	a.vpnMu.Lock()
	defer a.vpnMu.Unlock()
	contracts := a.contractStore()
	if contracts == nil {
		return errors.New("yuhaiin is not running")
	}
	cfg, err := a.androidTun()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if cfg.Enabled == enabled {
		if !enabled || !retry || vpnRunning() {
			return nil
		}
		// Enabled but not running (refused earlier or revoked): restart it.
		if inst := a.instanceSnapshot(); inst != nil {
			_ = inst.Inbound.Remove(cfg.ID)
		}
		return contracts.Retry(ctx, cfg.ID)
	}
	cfg.Enabled = enabled
	if err := contracts.Save(ctx, cfg, 0); err != nil {
		return fmt.Errorf("%s TUN inbound: %w", map[bool]string{true: "enable", false: "disable"}[enabled], err)
	}
	return nil
}

func vpnRunning() bool {
	switch platformvpn.Default.Status().State {
	case platformvpn.StateRunning, platformvpn.StateReconfiguring, platformvpn.StateEstablishing:
		return true
	}
	return false
}
