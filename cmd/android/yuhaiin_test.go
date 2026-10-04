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
	ctx := context.Background()
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
	}, "channel"); err != nil {
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
	ctx, cancel := context.WithCancel(context.Background())
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
