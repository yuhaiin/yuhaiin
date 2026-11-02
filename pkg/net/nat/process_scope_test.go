package nat

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type natScope struct{ name string }

func (*natScope) ProcessName(string, netapi.Address, netapi.Address) (netapi.Process, error) {
	return netapi.Process{}, net.ErrClosed
}

// Two isolated namespaces may use the same source address and port. Their
// UDP sources, sockets and reply bindings must stay separate, and each new
// mapping must carry its own namespace for process lookup.
func TestNATSeparatesProcessScopesWithSameSource(t *testing.T) {
	var mu sync.Mutex
	var remotes []net.Conn
	dials := make(chan netapi.ProcessDumper, 8)
	table := NewTable(nil, lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) {
		dials <- netapi.GetContext(ctx).ProcessScope()
		local, remote := net.Pipe()
		mu.Lock()
		remotes = append(remotes, remote)
		mu.Unlock()
		return &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}, nil
	}})
	defer func() {
		_ = table.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, remote := range remotes {
			_ = remote.Close()
		}
	}()
	source := &net.UDPAddr{IP: net.ParseIP("172.31.254.2"), Port: 40000}
	write := func(scope netapi.ProcessDumper) error {
		packet := netapi.NewPacket(source, netapi.ParseIPAddr("udp", net.ParseIP("192.0.2.8"), 53), pool.Clone([]byte("test")),
			netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { return len(b), nil }))
		defer packet.DecRef()
		packet.ProcessScope = scope
		netapi.WithInboundID("ssh")(packet)
		return table.Write(t.Context(), packet)
	}
	a, b := &natScope{"a"}, &natScope{"b"}
	for _, scope := range []netapi.ProcessDumper{a, b, a} {
		if err := write(scope); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []netapi.ProcessDumper{a, b} {
		select {
		case got := <-dials:
			if got != want {
				t.Fatalf("mapping carried scope %v, want %v", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("namespace %v reused another namespace's NAT source", want)
		}
	}
	select {
	case got := <-dials:
		t.Fatalf("extra socket for %v", got)
	case <-time.After(20 * time.Millisecond):
	}
	sourceKey, err := netapi.ParseSysAddr(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []netapi.ProcessDumper{a, b} {
		if _, ok := table.authenticatedSources.Load(authenticatedSourceKey{"", "ssh", scope, sourceKey.Comparable()}); !ok {
			t.Fatalf("missing NAT source for %v", scope)
		}
	}
	if _, ok := table.sourceControl.Load(sourceKey.Comparable()); ok {
		t.Fatal("scoped packet used the unscoped NAT source table")
	}
}
