package yuhaiin

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/migrate"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestListenAndroidHTTPPrefersPreviousPort(t *testing.T) {
	SetSavePath(t.TempDir())
	GetStore().PutBoolean(AllowLanKey, false)
	GetStore().PutInt(NewYuhaiinPortKey, -1)

	first, err := listenAndroidHTTP()
	if err != nil {
		t.Fatal(err)
	}
	port := listenerPort(t, first)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	GetStore().PutInt(NewYuhaiinPortKey, int32(port))
	second, err := listenAndroidHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got := listenerPort(t, second); got != port {
		t.Fatalf("listener port = %d, want previous port %d", got, port)
	}
}

func TestListenAndroidHTTPFallsBackWhenPreviousPortIsBusy(t *testing.T) {
	SetSavePath(t.TempDir())
	GetStore().PutBoolean(AllowLanKey, false)
	GetStore().PutInt(NewYuhaiinPortKey, -1)

	first, err := listenAndroidHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	port := listenerPort(t, first)

	GetStore().PutInt(NewYuhaiinPortKey, int32(port))
	second, err := listenAndroidHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got := listenerPort(t, second); got == port {
		t.Fatalf("fallback listener reused busy port %d", port)
	}
}

func listenerPort(t *testing.T, listener net.Listener) int {
	t.Helper()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestConfigureAndroidTUNEnablesPersistedInbound(t *testing.T) {
	ctx := t.Context()
	state := migrate.NewStateDB(filepath.Join(t.TempDir(), "state.db"))
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		t.Fatalf("migrate state: %v", err)
	}

	if err := configureAndroidTUN(ctx, state, &TUN{
		FD:       42,
		MTU:      1500,
		Portal:   "10.0.0.1/24",
		PortalV6: "fd00::1/64",
	}, "channel", "", "", ""); err != nil {
		t.Fatalf("configure Android TUN: %v", err)
	}

	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inbounds, err := plainstore.NewInboundStore(db).List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, inbound := range inbounds {
		if inbound.Protocol.Type != contractinbound.ProtocolTun {
			continue
		}
		if !inbound.Enabled {
			t.Fatal("Android TUN inbound is disabled")
		}
		if inbound.Protocol.Tun == nil || inbound.Protocol.Tun.Name != "fd://42" || inbound.Protocol.Tun.MTU != 1500 {
			t.Fatalf("unexpected Android TUN inbound: %+v", inbound)
		}
		if inbound.Protocol.Tun.Driver != "channel" {
			t.Fatalf("TUN driver = %q, want channel", inbound.Protocol.Tun.Driver)
		}
		return
	}
	t.Fatal("Android TUN inbound was not created")
}

func TestStopCancelsStartupBeforeWaitingForLifecycleLock(t *testing.T) {
	app := &App{}
	ctx, cancel := context.WithCancel(t.Context())
	app.setStartCancel(cancel)
	defer app.clearStartCancel()

	app.mu.Lock()
	stopped := make(chan struct{})
	go func() {
		_ = app.Stop()
		close(stopped)
	}()

	select {
	case <-ctx.Done():
		// Cancellation must happen before Stop can acquire app.mu.
	case <-time.After(time.Second):
		app.mu.Unlock()
		<-stopped
		t.Fatal("Stop waited for lifecycle lock before cancelling startup")
	}

	app.mu.Unlock()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not finish after lifecycle lock was released")
	}
}

func TestConfigureAndroidTUNStackSelection(t *testing.T) {
	for _, tc := range []struct {
		name, stack, cc, scheduler, driver           string
		wantStack, wantCC, wantScheduler, wantDriver string
		wantErr                                      bool
	}{
		{name: "legacy", driver: TunDriverSystemGvisorValue, wantDriver: TunDriverSystemGvisorValue},
		{name: "legacy ignores remembered options", driver: TunDriverFdbasedValue, cc: "bbr", scheduler: "fq_codel", wantDriver: TunDriverFdbasedValue},
		{name: "lightweight defaults to CUBIC and FIFO", driver: TunDriverSystemGvisorValue, stack: "lightweight", wantStack: "lightweight", wantDriver: TunDriverChannelValue},
		{name: "lightweight Reno", driver: TunDriverFdbasedValue, stack: "lightweight", cc: "reno", wantStack: "lightweight", wantCC: "reno", wantDriver: TunDriverChannelValue},
		{name: "lightweight CUBIC", driver: TunDriverFdbasedValue, stack: "lightweight", cc: "cubic", wantStack: "lightweight", wantCC: "cubic", wantDriver: TunDriverChannelValue},
		{name: "lightweight BBR", driver: TunDriverFdbasedValue, stack: "lightweight", cc: "bbr", wantStack: "lightweight", wantCC: "bbr", wantDriver: TunDriverChannelValue},
		{name: "lightweight explicit FIFO", driver: TunDriverSystemGvisorValue, stack: "lightweight", scheduler: "fifo", wantStack: "lightweight", wantScheduler: "fifo", wantDriver: TunDriverChannelValue},
		{name: "lightweight FQ-CoDel", driver: TunDriverSystemGvisorValue, stack: "lightweight", scheduler: "fq_codel", wantStack: "lightweight", wantScheduler: "fq_codel", wantDriver: TunDriverChannelValue},
		{name: "unknown stack", driver: TunDriverFdbasedValue, stack: "broken", wantErr: true},
		{name: "unknown algorithm", driver: TunDriverFdbasedValue, stack: "lightweight", cc: "broken", wantErr: true},
		{name: "unknown scheduler", driver: TunDriverFdbasedValue, stack: "lightweight", scheduler: "broken", wantErr: true},
		{name: "invalid lightweight MTU", driver: TunDriverFdbasedValue, stack: "lightweight", cc: "cubic", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			state := migrate.NewStateDB(filepath.Join(t.TempDir(), "state.db"))
			defer func() { _ = state.Close() }()
			if err := state.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			mtu := int32(1500)
			if tc.name == "invalid lightweight MTU" {
				mtu = 576
			}
			err := configureAndroidTUN(ctx, state, &TUN{
				FD: 42, MTU: mtu, Portal: "10.0.0.1/24", PortalV6: "fd00::1/64",
			}, tc.driver, tc.stack, tc.cc, tc.scheduler)
			if tc.wantErr {
				if err == nil {
					t.Fatal("invalid TUN selection was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			db, err := state.SQLDB(ctx)
			if err != nil {
				t.Fatal(err)
			}
			inbounds, err := plainstore.NewInboundStore(db).List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, in := range inbounds {
				if in.Protocol.Type != contractinbound.ProtocolTun {
					continue
				}
				if in.Protocol.Tun == nil {
					t.Fatal("nil TUN protocol")
				}
				got := in.Protocol.Tun
				if got.Stack != tc.wantStack || got.CongestionControl != tc.wantCC ||
					got.OutputScheduler != tc.wantScheduler || got.Driver != tc.wantDriver {
					t.Fatalf("TUN selection: stack=%q cc=%q scheduler=%q driver=%q; want %q %q %q %q",
						got.Stack, got.CongestionControl, got.OutputScheduler, got.Driver,
						tc.wantStack, tc.wantCC, tc.wantScheduler, tc.wantDriver)
				}
				found = true
			}
			if !found {
				t.Fatal("no TUN inbound persisted")
			}
		})
	}
}

// Reconfiguring an existing Android inbound must not retain stale lightweight
// settings after reverting to the legacy stack.
func TestConfigureAndroidTUNCanReturnToLegacy(t *testing.T) {
	ctx := t.Context()
	state := migrate.NewStateDB(filepath.Join(t.TempDir(), "state.db"))
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	tun := &TUN{FD: 42, MTU: 1500, Portal: "10.0.0.1/24", PortalV6: "fd00::1/64"}
	if err := configureAndroidTUN(ctx, state, tun, TunDriverFdbasedValue, "lightweight", "bbr", "fq_codel"); err != nil {
		t.Fatal(err)
	}
	if err := configureAndroidTUN(ctx, state, tun, TunDriverSystemGvisorValue, "", "bbr", "fq_codel"); err != nil {
		t.Fatal(err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inbounds, err := plainstore.NewInboundStore(db).List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range inbounds {
		if in.Protocol.Type != contractinbound.ProtocolTun {
			continue
		}
		got := in.Protocol.Tun
		if got == nil || got.Stack != "" || got.CongestionControl != "" || got.OutputScheduler != "" || got.Driver != TunDriverSystemGvisorValue {
			t.Fatalf("legacy TUN was not restored: %+v", got)
		}
		return
	}
	t.Fatal("no TUN inbound found")
}
