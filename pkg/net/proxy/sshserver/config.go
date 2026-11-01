// Package sshserver provides Linux-only SSH session execution through
// Yuhaiin's normal inbound routing pipeline.
package sshserver

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/yuhaiin/sessionnet"
	gossh "golang.org/x/crypto/ssh"
)

// Config deliberately uses a single SSH identity. User management and
// filesystem isolation are separate features and must not be inferred from
// authenticating a public key.
type Config struct {
	Listen           string
	HostKey          string
	Username         string
	AuthorizedKey    string
	UID              uint32
	GID              uint32
	Shell            string
	MTU              int
	GatewayIPv4      string
	SessionIPv4      string
	GatewayIPv6      string
	SessionIPv6      string
	FakeIPRanges     [2]netip.Prefix
	IPv6             bool
	MaxSessions      int
	AllowUnsafeShell bool
}

func (c *Config) validate() (gossh.Signer, gossh.PublicKey, error) {
	if !c.AllowUnsafeShell {
		return nil, nil, errors.New("ssh inbound: enable allowUnsafeShell only on a trusted host; network namespaces do not isolate the filesystem")
	}
	if c.Listen == "" {
		return nil, nil, errors.New("ssh inbound: listen address is required")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return nil, nil, fmt.Errorf("ssh inbound listen: %w", err)
	}
	if strings.TrimSpace(c.Username) == "" || strings.ContainsAny(c.Username, "\x00\r\n") {
		return nil, nil, errors.New("ssh inbound: username is required")
	}
	if c.UID == 0 || c.GID == 0 {
		return nil, nil, errors.New("ssh inbound: non-root UID and GID are required")
	}
	if c.Shell == "" {
		c.Shell = "/bin/sh"
	}
	if !strings.HasPrefix(c.Shell, "/") {
		return nil, nil, errors.New("ssh inbound: shell must be an absolute path")
	}
	if c.MTU == 0 {
		c.MTU = 1500
	}
	if c.MTU < 1280 || c.MTU > 9000 {
		return nil, nil, errors.New("ssh inbound: MTU must be 1280..9000")
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 8
	}
	if c.MaxSessions < 1 || c.MaxSessions > 128 {
		return nil, nil, errors.New("ssh inbound: maxSessions must be 1..128")
	}
	hostKey, err := gossh.ParsePrivateKey([]byte(c.HostKey))
	if err != nil {
		return nil, nil, fmt.Errorf("ssh inbound: invalid hostKey: %w", err)
	}
	key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(c.AuthorizedKey))
	if err != nil {
		return nil, nil, fmt.Errorf("ssh inbound: invalid authorizedKey: %w", err)
	}
	return hostKey, key, nil
}

// resolveAddresses selects and validates non-overlapping session links.
func (c Config) resolveAddresses() (sessionnet.AddressConfig, error) {
	var addr sessionnet.AddressConfig
	var err error
	if c.GatewayIPv4 != "" {
		addr.GatewayIPv4, err = netip.ParseAddr(c.GatewayIPv4)
		if err != nil { return addr, fmt.Errorf("ssh inbound gatewayIPv4: %w", err) }
	}
	if c.SessionIPv4 != "" {
		addr.SessionIPv4, err = netip.ParsePrefix(c.SessionIPv4)
		if err != nil { return addr, fmt.Errorf("ssh inbound sessionIPv4: %w", err) }
	}
	if c.GatewayIPv6 != "" {
		addr.GatewayIPv6, err = netip.ParseAddr(c.GatewayIPv6)
		if err != nil { return addr, fmt.Errorf("ssh inbound gatewayIPv6: %w", err) }
	}
	if c.SessionIPv6 != "" {
		addr.SessionIPv6, err = netip.ParsePrefix(c.SessionIPv6)
		if err != nil { return addr, fmt.Errorf("ssh inbound sessionIPv6: %w", err) }
	}
	addr, err = addr.Resolve(c.IPv6)
	if err != nil { return addr, err }
	if err := checkFakeIPOverlap(addr, c.FakeIPRanges, c.IPv6); err != nil {
		return sessionnet.AddressConfig{}, err
	}
	return addr, nil
}

func checkFakeIPOverlap(addr sessionnet.AddressConfig, pools [2]netip.Prefix, ipv6 bool) error {
	if pools[0].IsValid() && addr.SessionIPv4.Masked().Overlaps(pools[0]) {
		return fmt.Errorf("ssh inbound IPv4 link %s overlaps active FakeIP pool %s", addr.SessionIPv4.Masked(), pools[0])
	}
	if ipv6 && pools[1].IsValid() && addr.SessionIPv6.Masked().Overlaps(pools[1]) {
		return fmt.Errorf("ssh inbound IPv6 link %s overlaps active FakeIP pool %s", addr.SessionIPv6.Masked(), pools[1])
	}
	return nil
}
