package yuhaiin

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/platformvpn"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func testStateDB(t *testing.T) *sql.DB {
	t.Helper()
	state := migrate.NewStateDB(filepath.Join(t.TempDir(), "state.db"))
	t.Cleanup(func() { _ = state.Close() })
	if err := state.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	db, err := state.SQLDB(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// legacyV1ConfigureTUN reproduces what the v1 Android APK writes on every VPN
// start, so the migration and rollback contract can be tested.
func legacyV1ConfigureTUN(ctx context.Context, db *sql.DB, fd int, cc string) error {
	store := plainstore.NewInboundStore(db)
	return store.Save(ctx, contractinbound.Inbound{ID: "tun", Name: "tun", Enabled: true,
		Network: contractinbound.NewTypedNetwork(contractinbound.EmptyNetwork{}),
		Protocol: contractinbound.NewTypedProtocol(contractinbound.TunProtocol{
			Stack: "lightweight", CongestionControl: cc, Name: fmt.Sprintf("fd://%d", fd), MTU: 1500,
			SkipMulticast: true, Driver: "channel", Portal: "10.0.0.1/24", PortalV6: "fd00::1/64",
		})}, 0)
}

func androidTunOf(t *testing.T, db *sql.DB) contractinbound.Inbound {
	t.Helper()
	list, err := plainstore.NewInboundStore(db).List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	in, ok := findAndroidTun(list)
	if !ok {
		t.Fatal("android TUN inbound missing")
	}
	return in
}

func TestEnsureAndroidTUNCreatesDisabledPlatformInbound(t *testing.T) {
	SetSavePath(t.TempDir())
	db := testStateDB(t)
	if err := ensureAndroidTUNInbound(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	in := androidTunOf(t, db)
	if in.Enabled {
		t.Fatal("a fresh install must not start a VPN")
	}
	tun := in.Protocol.Tun
	if tun.Name != platformvpn.DeviceName || !tun.AutoFakeIPRoute || tun.Stack != "lightweight" || tun.Driver != "channel" {
		t.Fatalf("unexpected inbound %+v", tun)
	}
	// Idempotent.
	if err := ensureAndroidTUNInbound(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	list, _ := plainstore.NewInboundStore(db).List(t.Context())
	tuns := 0
	for _, in := range list {
		if in.Protocol.Type == contractinbound.ProtocolTun {
			tuns++
		}
	}
	if tuns != 1 {
		t.Fatalf("TUN inbounds = %d", tuns)
	}
}

func TestEnsureAndroidTUNMigratesLegacyAndStaysRollbackSafe(t *testing.T) {
	SetSavePath(t.TempDir())
	db := testStateDB(t)
	ctx := t.Context()
	if err := legacyV1ConfigureTUN(ctx, db, 42, "bbr"); err != nil {
		t.Fatal(err)
	}
	if err := ensureAndroidTUNInbound(ctx, db); err != nil {
		t.Fatal(err)
	}
	in := androidTunOf(t, db)
	if in.Enabled || in.Protocol.Tun.Name != platformvpn.DeviceName || in.Protocol.Tun.MTU != 0 || in.Protocol.Tun.Portal != "" {
		t.Fatalf("legacy inbound not migrated: enabled=%v %+v", in.Enabled, in.Protocol.Tun)
	}
	if in.Protocol.Tun.CongestionControl != "bbr" {
		t.Fatal("user TUN tuning lost")
	}
	// The user enables and tunes the VPN in v2; later starts keep it.
	in.Enabled = true
	in.Protocol.Tun.MTU = 1400
	if err := plainstore.NewInboundStore(db).Save(ctx, in, 0); err != nil {
		t.Fatal(err)
	}
	if err := ensureAndroidTUNInbound(ctx, db); err != nil {
		t.Fatal(err)
	}
	if got := androidTunOf(t, db); !got.Enabled || got.Protocol.Tun.MTU != 1400 {
		t.Fatal("v2 configuration was overwritten")
	}
	// Rollback: a v1 APK rewrites the inbound on its next VPN start.
	if err := legacyV1ConfigureTUN(ctx, db, 7, "cubic"); err != nil {
		t.Fatal(err)
	}
	if got := androidTunOf(t, db); got.Protocol.Tun.Name != "fd://7" || !got.Enabled {
		t.Fatalf("v1 rollback could not reuse the inbound: %+v", got.Protocol.Tun)
	}
}

func TestAndroidVPNMTUProfile(t *testing.T) {
	for profile, want := range map[string]int32{"": 9000, "auto": 9000, "9000": 9000, "1500": 1500} {
		if got := androidVPNMTU(profile); got != want {
			t.Errorf("%q => %d, want %d", profile, got, want)
		}
	}
}

type recordingVpnProvider struct {
	auth     string
	statuses []string
}

func (p *recordingVpnProvider) Establish(int64, string) (int32, error) {
	return -1, fmt.Errorf("unused")
}
func (p *recordingVpnProvider) Release(int64)          {}
func (p *recordingVpnProvider) Authorization() string  { return p.auth }
func (p *recordingVpnProvider) StatusChanged(s string) { p.statuses = append(p.statuses, s) }

func TestSetVpnProviderRegistersAuthorization(t *testing.T) {
	p := &recordingVpnProvider{auth: `{"prepared":true,"consent":false}`}
	SetVpnProvider(p)
	t.Cleanup(func() { SetVpnProvider(nil) })
	auth, ok := currentAuthorization()
	if !ok || !auth.Prepared || auth.Consent {
		t.Fatalf("auth = %+v %v", auth, ok)
	}
	if platformvpn.Default.Provider() == nil {
		t.Fatal("provider not registered")
	}
	SetVpnProvider(nil)
	if platformvpn.Default.Provider() != nil {
		t.Fatal("provider not cleared")
	}
}

func TestNotifyVpnRevokedIgnoresUnknownGeneration(t *testing.T) {
	if NotifyVpnRevoked(0) || NotifyVpnRevoked(987654) {
		t.Fatal("unknown generation must be ignored")
	}
}
