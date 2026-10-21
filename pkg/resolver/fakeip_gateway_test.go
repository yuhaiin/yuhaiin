package resolver

import (
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestFakeIPGatewaySelectedConnectionRetainsOriginalLease(t *testing.T) {
	for _, selectedHost := range []string{"origin.example", "203.0.113.8"} {
		t.Run(selectedHost, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			f, err := NewFakeDNS(netapi.NewErrProxy(errors.New("unexpected route selection")),
				netapi.ErrorResolver(func(string) error { return nil }), path,
				contractresolver.FakeDNS{IPv4Range: "198.18.0.1/32"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			db, err := sqlite.Open(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			lookup := func(domain string) error {
				_, err := f.fake.LookupIP(t.Context(), domain, func(o *netapi.LookupIPOption) {
					o.Mode = netapi.ResolverModePreferIPv4
				})
				return err
			}
			if err := lookup("origin.example"); err != nil {
				t.Fatal(err)
			}
			ctx := netapi.WithContext(t.Context())
			original := netapi.ParseNetipAddr("tcp", netip.MustParseAddr("198.18.0.1"), 443)
			if target := f.RecoverDestination(ctx, original); !target.IsFqdn() {
				t.Fatalf("destination was not recovered: %v", target)
			}
			selected, err := netapi.ParseAddressPort("tcp", selectedHost, 443)
			if err != nil {
				t.Fatal(err)
			}
			age := func() {
				t.Helper()
				if _, err := db.DB().ExecContext(t.Context(), `UPDATE fakeip_entries SET last_used_at = ?`, time.Now().Add(-2*time.Hour).UnixNano()); err != nil {
					t.Fatal(err)
				}
			}
			local, remote := net.Pipe()
			t.Cleanup(func() { _ = local.Close(); _ = remote.Close() })
			conn, err := f.ConnWithLease(ctx, selected, func() (net.Conn, error) {
				age()
				if err := lookup("replacement.example"); err == nil {
					t.Fatal("original mapping was reused during selected outbound dial")
				}
				return local, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := lookup("replacement.example"); err == nil {
				t.Fatal("original mapping was reused while the Gateway connection was open")
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			// Publish any final activity touch before simulating another idle period.
			_ = lookup("replacement.example")
			age()
			if err := lookup("replacement.example"); err != nil {
				t.Fatalf("closed Gateway connection retained its lease: %v", err)
			}
			dialErr := errors.New("selected outbound unavailable")
			if _, err := f.ConnWithLease(ctx, selected, func() (net.Conn, error) {
				return nil, dialErr
			}); !errors.Is(err, dialErr) {
				t.Fatalf("selected dial error = %v", err)
			}
			_ = lookup("after-failure.example")
			age()
			if err := lookup("after-failure.example"); err != nil {
				t.Fatalf("failed Gateway dial retained its lease: %v", err)
			}
		})
	}
}
