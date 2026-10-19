package nebula

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"empty", "", "required"},
		{"invalid YAML", "pki: [", "parse configuration"},
		{"system tun disabled", "tun:\n  disabled: true\n", "unsupported"},
		{"system routes", "tun:\n  use_system_route_table: true\n", "unsupported"},
		{"unsafe routes", "tun:\n  unsafe_routes:\n    - route: 10.0.0.0/8\n", "routing"},
		{"SSH listener", "sshd:\n  enabled: true\n", "disabled"},
		{"Lighthouse DNS", "lighthouse:\n  serve_dns: true\n", "disabled"},
		{"stats listener", "stats:\n  type: prometheus\n", "disabled"},
		{"multiqueue", "routines: 2\n", "multiple"},
		{"tiny MTU", "tun:\n  mtu: 100\n", "invalid MTU"},
		{"valid userspace config", "listen:\n  host: 0.0.0.0\n  port: 0\ntun:\n  mtu: 1300\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.yaml, log)
			if tt.want == "" {
				if err != nil { t.Fatalf("unexpected error: %v", err) }
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v; want substring %q", err, tt.want)
			}
		})
	}
}
