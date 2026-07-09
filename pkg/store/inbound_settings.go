package store

import (
	"context"
	"errors"
	"fmt"
)

type InboundSettings struct {
	HijackDNS       bool
	HijackDNSFakeIP bool
	Sniff           bool
}

func (s *InboundStore) Settings(ctx context.Context) (InboundSettings, error) {
	if s == nil || s.db == nil {
		return InboundSettings{}, errors.New("inbound store database is nil")
	}
	var settings InboundSettings
	var hijackDNS, hijackDNSFakeIP, sniff int
	err := s.db.QueryRowContext(ctx, `
		SELECT hijack_dns, hijack_dns_fakeip, sniff_enabled
		FROM inbound_settings
		WHERE id = 1
	`).Scan(&hijackDNS, &hijackDNSFakeIP, &sniff)
	if err != nil {
		return InboundSettings{}, fmt.Errorf("query inbound settings failed: %w", err)
	}
	settings.HijackDNS = hijackDNS != 0
	settings.HijackDNSFakeIP = hijackDNSFakeIP != 0
	settings.Sniff = sniff != 0
	return settings, nil
}

func (s *InboundStore) SaveSettings(ctx context.Context, settings InboundSettings) error {
	if s == nil || s.db == nil {
		return errors.New("inbound store database is nil")
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO inbound_settings(id, hijack_dns, hijack_dns_fakeip, sniff_enabled)
		VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hijack_dns = excluded.hijack_dns,
			hijack_dns_fakeip = excluded.hijack_dns_fakeip,
			sniff_enabled = excluded.sniff_enabled
	`, boolToInt(settings.HijackDNS), boolToInt(settings.HijackDNSFakeIP), boolToInt(settings.Sniff)); err != nil {
		return fmt.Errorf("save inbound settings failed: %w", err)
	}
	return nil
}
