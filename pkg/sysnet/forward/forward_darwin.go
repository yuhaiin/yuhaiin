package forward

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
)

const (
	darwinSysctlIPv4 = "net.inet.ip.forwarding"
	darwinSysctlIPv6 = "net.inet6.ip6.forwarding"
)

// Manager applies forwarding plans on macOS with sysctl and the Yuhaiin PF
// anchor. It never edits /etc/pf.conf or other anchors, and enables PF with a
// reference-counted token that it releases on Close.
type Manager struct {
	Sysctl *Sysctl
	// run executes a command with stdin; replaced in tests.
	run     func(stdin string, name string, args ...string) (string, error)
	token   string
	loaded  bool
	applied string
}

func runCommand(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func New() *Manager {
	m := &Manager{run: runCommand}
	m.Sysctl = &Sysctl{
		ReadValue: func(key string) (string, error) { return m.run("", "/usr/sbin/sysctl", "-n", key) },
		WriteValue: func(key, value string) error {
			_, err := m.run("", "/usr/sbin/sysctl", "-w", key+"="+value)
			return err
		},
	}
	return m
}

// Supported reports whether this platform has a forwarding applier.
func Supported() bool { return true }

// nextHop returns an interface's own address of the family, the next hop
// macOS uses for point-to-point interfaces such as utun.
func nextHop(link int, v6 bool) (netip.Addr, error) {
	ifc, err := net.InterfaceByIndex(link)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is6() == v6 && !ip.IsLinkLocalUnicast() {
				return ip.Unmap(), nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("interface %s has no %s address; set a gateway for this egress", ifc.Name, pfFamily(v6))
}

var pfToken = regexp.MustCompile(`Token : (\d+)`)

// checkAnchors verifies that the main ruleset evaluates com.apple/*, which
// the default /etc/pf.conf does. A customized pf.conf without it would make
// the Yuhaiin anchor silently ineffective.
func (m *Manager) checkAnchors() error {
	rules, err := m.run("", "/sbin/pfctl", "-s", "rules")
	if err != nil {
		return err
	}
	nat, err := m.run("", "/sbin/pfctl", "-s", "nat")
	if err != nil {
		return err
	}
	if !strings.Contains(rules, `anchor "com.apple/*"`) || !strings.Contains(nat, `nat-anchor "com.apple/*"`) {
		return errors.New(`the PF main ruleset does not evaluate the "com.apple/*" anchors (restore the default /etc/pf.conf lines anchor and nat-anchor "com.apple/*")`)
	}
	return nil
}

// Apply loads the plan's PF rules into the Yuhaiin anchor (an atomic
// replacement of that anchor only), enables PF through a token, and sets the
// forwarding sysctls. An empty plan flushes the anchor, releases the token and
// restores the sysctls.
func (m *Manager) Apply(plan Plan) error {
	rules, err := CompilePF(plan, nextHop)
	if err != nil {
		return err
	}
	if rules == m.applied && (rules != "" || !m.loaded) {
		return errors.Join(m.Sysctl.Set(darwinSysctlIPv4, plan.IPv4), m.Sysctl.Set(darwinSysctlIPv6, plan.IPv6))
	}
	if rules == "" {
		var result error
		result = errors.Join(result, m.Sysctl.Set(darwinSysctlIPv4, plan.IPv4), m.Sysctl.Set(darwinSysctlIPv6, plan.IPv6))
		if m.loaded {
			if _, err := m.run("", "/sbin/pfctl", "-a", PFAnchor, "-F", "all"); err != nil {
				result = errors.Join(result, err)
			} else {
				m.loaded, m.applied = false, ""
			}
		}
		if m.token != "" {
			if _, err := m.run("", "/sbin/pfctl", "-X", m.token); err != nil {
				result = errors.Join(result, err)
			} else {
				m.token = ""
			}
		}
		return result
	}
	if err := m.checkAnchors(); err != nil {
		return err
	}
	// Parse first: a rejected ruleset leaves the previous anchor untouched.
	if _, err := m.run(rules, "/sbin/pfctl", "-n", "-a", PFAnchor, "-f", "-"); err != nil {
		return fmt.Errorf("PF rejected the forwarding rules: %w", err)
	}
	if _, err := m.run(rules, "/sbin/pfctl", "-a", PFAnchor, "-f", "-"); err != nil {
		return err
	}
	m.loaded, m.applied = true, rules
	if m.token == "" {
		out, err := m.run("", "/sbin/pfctl", "-E")
		if err != nil {
			return err
		}
		if match := pfToken.FindStringSubmatch(out); match != nil {
			m.token = match[1]
		}
	}
	return errors.Join(m.Sysctl.Set(darwinSysctlIPv4, plan.IPv4), m.Sysctl.Set(darwinSysctlIPv6, plan.IPv6))
}

// Close removes the anchor's rules, releases PF and restores the sysctls.
func (m *Manager) Close() error { return m.Apply(Plan{}) }
