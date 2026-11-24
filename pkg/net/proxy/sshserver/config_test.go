package sshserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/yuhaiin/sessionnet"
	gossh "golang.org/x/crypto/ssh"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	_, host, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(host)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Listen: "127.0.0.1:0", HostKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		Username: "alice", AuthorizedKey: string(gossh.MarshalAuthorizedKey(key)),
		NamespaceMode: NamespaceModeRootful, UID: 65534, GID: 65534, AllowUnsafeShell: true,
	}
}

func TestValidate(t *testing.T) {
	cfg := testConfig(t)
	if _, _, err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Shell != "/bin/sh" || cfg.MTU != 1500 || cfg.MaxSessions != 8 || cfg.Timezone != "" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	cfg.Timezone = "UTC"
	if _, _, err := cfg.validate(); err != nil {
		t.Fatalf("valid timezone rejected: %v", err)
	}
	tests := []struct {
		name   string
		modify func(*Config)
		want   string
	}{
		{"unsafe disabled", func(c *Config) { c.AllowUnsafeShell = false }, "allowUnsafeShell"},
		{"root uid", func(c *Config) { c.UID = 0 }, "non-root"},
		{"root gid", func(c *Config) { c.GID = 0 }, "non-root"},
		{"unknown mode", func(c *Config) { c.NamespaceMode = "auto" }, "namespaceMode"},
		{"relative shell", func(c *Config) { c.Shell = "sh" }, "absolute"},
		{"invalid timezone", func(c *Config) { c.Timezone = "Mars/Olympus" }, "timezone"},
		{"relative timezone path", func(c *Config) { c.Timezone = "../etc/passwd" }, "timezone"},
		{"timezone with newline", func(c *Config) { c.Timezone = "UTC\nTZ=UTC" }, "timezone"},
		{"relative SFTP directory", func(c *Config) { c.SFTPReadOnlyPaths = []string{"archive"} }, "sftpReadOnlyPaths"},
		{"invalid SFTP directory", func(c *Config) { c.SFTPReadOnlyPaths = []string{"/archive\x00"} }, "sftpReadOnlyPaths"},
		{"no auth key", func(c *Config) { c.AuthorizedKey = "" }, "authorizedKey"},
		{"no host key", func(c *Config) { c.HostKey = "" }, "hostKey"},
		{"bad mtu", func(c *Config) { c.MTU = 1000 }, "MTU"},
		{"too many sessions", func(c *Config) { c.MaxSessions = 999 }, "maxSessions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testConfig(t)
			tt.modify(&c)
			_, _, err := c.validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validation got %v, expected substring %q", err, tt.want)
			}
		})
	}
}

func TestValidateNamespaceMode(t *testing.T) {
	c := testConfig(t)
	c.NamespaceMode, c.UID, c.GID = "", 0, 0
	if _, _, err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.NamespaceMode != NamespaceModeRootless || c.sessionMode() != sessionnet.ModeRootless {
		t.Fatalf("saved inbounds without a mode must be rootless: %q", c.NamespaceMode)
	}
	if c.UID != uint32(os.Geteuid()) || c.GID != uint32(os.Getegid()) {
		t.Fatalf("rootless default IDs %d:%d, want the Yuhaiin user", c.UID, c.GID)
	}
	c = testConfig(t)
	c.NamespaceMode, c.UID = NamespaceModeRootful, 0
	if _, _, err := c.validate(); err == nil {
		t.Fatal("rootful mode must require an explicit non-root UID")
	}
}

func TestResolveAddresses(t *testing.T) {
	c := testConfig(t)
	a, err := c.resolveAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if a.GatewayIPv4.String() != sessionnet.GatewayIPv4 {
		t.Fatalf("unexpected default gateway %s", a.GatewayIPv4)
	}
	c.FakeIPRanges[0] = netip.MustParsePrefix("172.31.0.0/16")
	if _, err = c.resolveAddresses(); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("expected fakeip collision, got %v", err)
	}
	c.GatewayIPv4, c.SessionIPv4 = "10.250.253.1", "10.250.253.2/30"
	if _, err = c.resolveAddresses(); err != nil {
		t.Fatal(err)
	}
	c.GatewayIPv4 = "198.18.0.1"
	c.SessionIPv4 = "198.18.0.2/30"
	c.FakeIPRanges[0] = netip.MustParsePrefix("198.18.0.0/16")
	if _, err = c.resolveAddresses(); err == nil {
		t.Fatal("expected legacy address collision to be rejected")
	}
}
