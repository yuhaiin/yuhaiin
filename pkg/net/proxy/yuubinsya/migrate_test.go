package yuubinsya

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
)

type migrationDialer struct {
	netapi.Proxy
	calls atomic.Int32
}

func (d *migrationDialer) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	d.calls.Add(1)
	return d.Proxy.PacketConn(ctx, addr)
}

func TestUOTMigrationReusesLiveNATSession(t *testing.T) {
	for _, coalesce := range []bool{false, true} {
		t.Run(strconv.FormatBool(coalesce), func(t *testing.T) { testUOTMigration(t, coalesce) })
	}
}

func testUOTMigration(t *testing.T, coalesce bool) {
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	sources := make(chan string, 4)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			sources <- addr.String()
			if _, err := echo.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	target, err := netapi.ParseSysAddr(echo.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	outbound := &migrationDialer{Proxy: direct.NewDirect()}
	table := nat.NewTable(nil, outbound)
	defer table.Close()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{Password: "migration-test", UDPCoalesce: coalesce}, netapi.NewListener(lis, &mockPacket{}), mockHandlerPacket(func(pkt *netapi.Packet) {
		defer pkt.DecRef()
		if err := table.Write(t.Context(), pkt); err != nil {
			t.Errorf("forward packet: %v", err)
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	host, portText, _ := net.SplitHostPort(lis.Addr().String())
	port, _ := strconv.Atoi(portText)
	base, err := fixed.NewClient(fixed.Config{Host: host, Port: int32(port)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{Password: "migration-test", UDPOverStream: true, UDPCoalesce: coalesce}, base)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	open := func(id uint64) (net.PacketConn, uint64) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		store := netapi.WithContext(ctx)
		store.SetUDPMigrateID(id)
		conn, err := client.PacketConn(store, target)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn, store.GetUDPMigrateID()
	}
	exchange := func(conn net.PacketConn, payload string) string {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.WriteTo([]byte(payload), target); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 128)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("%s after migration: %v", payload, err)
		}
		if string(buf[:n]) != payload {
			t.Fatalf("reply=%q", buf[:n])
		}
		return <-sources
	}
	first, id := open(0)
	if id == 0 {
		t.Fatal("server did not allocate migration ID")
	}
	before := exchange(first, "before")
	_ = first.Close() // Disconnect only UOT; its remote UDP session remains alive.
	second, secondID := open(id)
	if secondID != id {
		t.Fatalf("migration ID changed: %d -> %d", id, secondID)
	}
	after := exchange(second, "after")
	if after != before {
		t.Fatalf("UDP source changed during migration: %s -> %s", before, after)
	}
	if got := outbound.calls.Load(); got != 1 {
		t.Fatalf("migration recreated %d UDP sessions", got)
	}
}
