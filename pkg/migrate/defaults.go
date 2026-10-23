package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"time"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/defaults"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

const initialDefaultsKey = "sqlite_initial_defaults_v1"

// initializeSQLiteDefaults populates the current contract model on a genuinely
// new installation. Existing SQLite installations, including databases created
// before this initializer existed, keep all their user state untouched.
func initializeSQLiteDefaults(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite defaults transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var marker string
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key = ?", initialDefaultsKey).Scan(&marker)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read sqlite defaults marker: %w", err)
	}
	if marker == "1" {
		return nil
	}

	// The former initializer marked completed plain-model upgrades. Do not
	// seed over an existing installation that predates this cleanup.
	var previouslyMigrated int
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM metadata WHERE key = 'plain_model_migration_done' AND value = '1')").Scan(&previouslyMigrated); err != nil {
		return err
	}
	var populated int
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS("+
		"SELECT 1 FROM settings_kv UNION ALL SELECT 1 FROM inbounds_v2 "+
		"UNION ALL SELECT 1 FROM resolvers_v2 UNION ALL SELECT 1 FROM nodes_v2 "+
		"UNION ALL SELECT 1 FROM route_rules_v2 UNION ALL SELECT 1 FROM route_lists_v2 "+
		"UNION ALL SELECT 1 FROM dns_settings)").Scan(&populated); err != nil {
		return fmt.Errorf("check sqlite initial state: %w", err)
	}

	if previouslyMigrated == 0 && populated == 0 {
		if err := seedDefaultSQLiteRows(ctx, tx); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx,
		"INSERT INTO metadata(key, value) VALUES (?, '1') ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		initialDefaultsKey); err != nil {
		return fmt.Errorf("mark sqlite defaults initialized: %w", err)
	}
	return tx.Commit()
}

func seedDefaultSQLiteRows(ctx context.Context, tx *sql.Tx) error {
	now := time.Now().Unix()
	for _, setting := range []struct {
		section, key, value string
	}{
		{"general", "ipv6", "true"},
		{"general", "use_default_interface", "true"},
		{"system_proxy", "http", "true"},
		{"system_proxy", "socks5", "false"},
		{"logcat", "level", "1"},
		{"logcat", "save", "true"},
	} {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO settings_kv(section, key, value_json, updated_at) VALUES (?, ?, ?, ?)",
			setting.section, setting.key, setting.value, now); err != nil {
			return fmt.Errorf("seed default setting %s.%s: %w", setting.section, setting.key, err)
		}
	}

	ipv4 := defaults.FakeipV4UlaGenerate().String()
	ipv6 := defaults.FakeipV6UlaGenerate().String()
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO dns_settings(id, server, fakedns_enabled, fakedns_ipv4_range, fakedns_ipv6_range) VALUES (1, ?, 0, ?, ?)",
		"127.0.0.1:5353", ipv4, ipv6); err != nil {
		return fmt.Errorf("seed default DNS settings: %w", err)
	}
	for _, pattern := range []string{
		"*.msftncsi.com", "*.msftconnecttest.com", "ping.archlinux.org",
		"mask.icloud.com", "mask-h2.icloud.com", "mask.apple-dns.net",
	} {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO dns_fakedns_lists(kind, value) VALUES ('whitelist', ?)", pattern); err != nil {
			return fmt.Errorf("seed fake-DNS whitelist: %w", err)
		}
	}

	if err := plainstore.SaveResolverContract(ctx, tx, contractresolver.Resolver{
		ID: "bootstrap", Name: "bootstrap", Type: "udp", Host: "8.8.8.8",
	}, now); err != nil {
		return fmt.Errorf("seed bootstrap resolver: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO inbound_settings(id, hijack_dns, hijack_dns_fakeip, sniff_enabled) VALUES (1, 1, 1, 1)"); err != nil {
		return fmt.Errorf("seed inbound settings: %w", err)
	}
	if err := plainstore.SaveInboundContract(ctx, tx, contractinbound.Inbound{
		ID: "mixed", Name: "mixed", Enabled: true,
		Network: contractinbound.NewTypedNetwork(contractinbound.TCPUDPNetwork{
			Host: "127.0.0.1:1080", UDP: contractinbound.UDPEnabled,
		}),
		Protocol: contractinbound.NewTypedProtocol(contractinbound.MixedProtocol{}),
	}, now); err != nil {
		return fmt.Errorf("seed default mixed inbound: %w", err)
	}
	tunName := "tun0"
	switch runtime.GOOS {
	case "darwin":
		tunName = "utun0"
	case "windows":
		tunName = "wintun"
	}
	if err := plainstore.SaveInboundContract(ctx, tx, contractinbound.Inbound{
		ID: "tun", Name: "tun", Enabled: false,
		Network: contractinbound.NewTypedNetwork(contractinbound.EmptyNetwork{}),
		Protocol: contractinbound.NewTypedProtocol(contractinbound.TunProtocol{
			Name: "tun://" + tunName, MTU: 9000, SkipMulticast: true,
			Driver:   "channel",
			Stack:    "lightweight",
			Portal:   defaults.TunV4UlaGenerate().String(),
			PortalV6: defaults.TunV6UlaGenerate().String(),
			Routes:   []string{ipv4, ipv6},
		}),
	}, now); err != nil {
		return fmt.Errorf("seed default TUN preset: %w", err)
	}
	if err := plainstore.SaveInboundContract(ctx, tx, contractinbound.Inbound{
		ID: "yuubinsya", Name: "yuubinsya", Enabled: false,
		Network: contractinbound.NewTypedNetwork(contractinbound.TCPUDPNetwork{
			Host: "127.0.0.1:40501", UDP: contractinbound.UDPTCPOnly,
		}),
		Protocol: contractinbound.NewTypedProtocol(contractinbound.YuubinsyaProtocol{Password: "password"}),
	}, now); err != nil {
		return fmt.Errorf("seed default Yuubinsya preset: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO route_settings(id, direct_resolver, proxy_resolver, resolve_locally, udp_proxy_fqdn, revision, default_mode, default_target_json) "+
			"VALUES (1, 'bootstrap', 'bootstrap', 0, 0, 1, 'proxy', '{\"type\":\"default\"}')"); err != nil {
		return fmt.Errorf("seed default route settings: %w", err)
	}

	if err := plainstore.SaveRouteListContract(ctx, tx, contractroute.RouteListDetail{
		ID: "LAN", Name: "LAN", Type: "host",
		Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{
			Lists: []string{
				"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
				"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/29",
				"192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
				"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
				"224.0.0.0/3", "fc00::/7", "fe80::/10", "ff00::/8", "localhost",
			},
		}},
	}, now); err != nil {
		return fmt.Errorf("seed LAN list: %w", err)
	}
	if err := plainstore.SaveRouteRuleContract(ctx, tx, contractroute.RouteRule{
		ID: "LAN", Name: "LAN", Mode: "direct",
		Target: contractroute.Target{Type: "default"},
		Rules: []contractroute.RuleExpr{{
			Type: "all", All: []contractroute.RuleExpr{{
				Type: "host", Host: &contractroute.ListRef{List: "LAN"},
			}},
		}},
	}, 0, now); err != nil {
		return fmt.Errorf("seed LAN routing rule: %w", err)
	}
	return nil
}
