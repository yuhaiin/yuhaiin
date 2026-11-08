package yuhaiin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
)

type CIDR struct {
	IP   string
	Mask int32
}

// ProxyGet fetches a URL through the configured Go proxy chain. It is exposed
// to the Android Compose updater through the generated AAR bindings.
func ProxyGet(rawURL string) ([]byte, error) {
	resp, err := updatepkg.NewProxyHTTPClient().Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("proxy request failed: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// ProxyDownload downloads a file through the configured Go proxy chain into
// destination. Callers should provide a temporary destination and atomically
// move it into place after this function returns successfully.
func ProxyDownload(rawURL, destination string) error {
	resp, err := updatepkg.NewProxyHTTPClient().Get(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("proxy download failed: %s", resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	tmp, err := os.Create(destination)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(destination)
	}
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, 512<<20)); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(destination)
		return err
	}
	return nil
}

func ParseCIDR(s string) (*CIDR, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}

	mask, _ := ipNet.Mask.Size()
	ip := ipNet.IP.String()
	return &CIDR{IP: ip, Mask: int32(mask)}, nil
}

type AddRoute interface {
	Add(*CIDR)
}

// withStateDB opens the Android state database with the same migration and
// first-run seeding used by App.Start, so values read before the core starts
// are the values the core will load afterwards.
func withStateDB(ctx context.Context, fn func(*sql.DB) error) error {
	if savepath == "" {
		return errors.New("configuration path is not initialized")
	}
	state := migrate.NewStateDB(paths.PathGenerator.State(savepath))
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		return fmt.Errorf("open state database: %w", err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		return err
	}
	return fn(db)
}

// fakeDNSRoutes returns the IPv4 and IPv6 FakeIP pools the Go core will use.
// A missing dns_settings row and empty or invalid ranges resolve to the shared
// defaults through configuration.GetFakeIPRange, exactly as the resolver does.
func fakeDNSRoutes(ctx context.Context) ([]netip.Prefix, error) {
	var config contractresolver.FakeDNS
	err := withStateDB(ctx, func(db *sql.DB) error {
		var err error
		config, err = plainstore.NewResolverConfigStore(db).FakeDNS(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("read fakedns config: %w", err)
	}

	routes := make([]netip.Prefix, 0, 2)
	for _, value := range []struct {
		raw  string
		ipv6 bool
	}{{config.IPv4Range, false}, {config.IPv6Range, true}} {
		prefix := configuration.GetFakeIPRange(value.raw, value.ipv6)
		if value.raw == "" {
			log.Info("fakedns range is not configured, using default", "ipv6", value.ipv6, "range", prefix)
		} else if parsed, err := netip.ParsePrefix(value.raw); err != nil || parsed.Masked() != prefix {
			log.Warn("invalid fakedns range, using default", "ipv6", value.ipv6, "range", value.raw, "default", prefix)
		}
		routes = append(routes, prefix)
	}
	return routes, nil
}

func IsIPv6() bool {
	var ipv6 bool
	err := withStateDB(context.Background(), func(db *sql.DB) error {
		settings, err := plainstore.NewSettingsStore(db).Load(context.Background())
		if err != nil {
			return err
		}
		ipv6 = settings.IPv6
		return nil
	})
	if err != nil {
		log.Error("load ipv6 setting failed", "err", err)
		return false
	}
	return ipv6
}

// AddFakeDnsCidr adds the FakeIP routes the core will serve. Database errors
// are returned so VPN startup fails visibly instead of silently omitting the
// routes.
func AddFakeDnsCidr(process AddRoute) error {
	routes, err := fakeDNSRoutes(context.Background())
	if err != nil {
		log.Error("get fakedns routes failed", "err", err)
		return err
	}
	for _, prefix := range routes {
		process.Add(&CIDR{IP: prefix.Addr().String(), Mask: int32(prefix.Bits())})
	}
	return nil
}
