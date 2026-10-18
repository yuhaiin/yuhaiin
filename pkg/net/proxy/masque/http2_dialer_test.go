package masque

import (
	"net"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

func TestHTTP2OuterConnectionHonorsLoopProtection(t *testing.T) {
	const iface = "masque-test-skip-interface"
	// The app installs a persistent skip set; the standalone dialer default
	// creates an empty set on each call.
	skipped := set.NewSet[string]()
	skipped.Push(iface)
	previous := dialer.SkipInterface
	dialer.SkipInterface = func() *set.Set[string] { return skipped }
	t.Cleanup(func() { dialer.SkipInterface = previous })
	ctx := netapi.WithContext(t.Context())
	ctx.ConnOptions().SetBindInterface(iface)
	lis, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().(*net.TCPAddr)
	_ = lis.Close()
	m := &Masque{addr: &net.UDPAddr{IP: addr.IP, Port: addr.Port}}
	if conn, err := m.connectHTTP2(ctx); err == nil || !strings.Contains(err.Error(), "skip infinite loop") {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("outer TCP dial bypassed loop protection: %v", err)
	}
}
