package forward

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
)

const (
	darwinSysctlIPv4 = "net.inet.ip.forwarding"
	darwinSysctlIPv6 = "net.inet6.ip6.forwarding"
)

// Manager applies forwarding plans on macOS with sysctl and the Yuhaiin PF
// anchor io.github.yuhaiin/forward. The only /etc/pf.conf change is the
// managed registration of Yuhaiin's anchor (shared with Network
// Protection); other anchors are never touched. PF is enabled with a
// reference-counted token that it releases on Close.
type Manager struct {
	Sysctl *Sysctl
	// run executes a command with stdin; replaced in tests.
	run func(stdin string, name string, args ...string) (string, error)
	// pfConf is the main ruleset file; replaced in tests.
	pfConf  string
	pfState string
	token   string
	loaded  bool
	applied string
	legacy  bool
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
	m := &Manager{run: runCommand, pfConf: "/etc/pf.conf", pfState: pf.BackupDir}
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

// legacyPFAnchor is where earlier versions loaded the forwarding rules. It
// is flushed once when forwarding starts, so old rules cannot linger.
const legacyPFAnchor = "com.apple/yuhaiin"

var pfToken = regexp.MustCompile(`Token : (\d+)`)

// checkAnchors makes the main ruleset evaluate Yuhaiin's anchors (adding the
// managed pf.conf lines if needed) and, when the plan masquerades, its NAT
// anchor too.
func (m *Manager) checkAnchors(needNAT bool) error {
	e := pf.NewEngine(m.pfState)
	e.Anchor, e.Conf = PFAnchor, m.pfConf
	e.Run = func(_ context.Context, stdin, name string, args ...string) (string, error) {
		return m.run(stdin, name, args...)
	}
	if _, err := e.EnsureRegistered(context.Background(), true); err != nil {
		return err
	}
	if !needNAT {
		return nil
	}
	nat, err := m.run("", "/sbin/pfctl", "-s", "nat")
	if err != nil {
		return err
	}
	if !pf.MainReferences(nat, "nat-anchor") {
		return errors.New(`the PF main ruleset does not evaluate nat-anchor "` + pf.Anchor + `/*", which masquerade needs; check /etc/pf.conf`)
	}
	return nil
}

// flushLegacy removes rules earlier versions loaded into com.apple/yuhaiin.
// That anchor only ever held Yuhaiin's own forwarding rules.
func (m *Manager) flushLegacy() {
	if m.legacy {
		return
	}
	m.legacy = true
	rules, _ := m.run("", "/sbin/pfctl", "-a", legacyPFAnchor, "-s", "rules")
	nat, _ := m.run("", "/sbin/pfctl", "-a", legacyPFAnchor, "-s", "nat")
	if strings.TrimSpace(rules) != "" || strings.TrimSpace(nat) != "" {
		_, _ = m.run("", "/sbin/pfctl", "-a", legacyPFAnchor, "-F", "rules")
		_, _ = m.run("", "/sbin/pfctl", "-a", legacyPFAnchor, "-F", "nat")
	}
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
			_, err1 := m.run("", "/sbin/pfctl", "-a", PFAnchor, "-F", "rules")
			_, err2 := m.run("", "/sbin/pfctl", "-a", PFAnchor, "-F", "nat")
			if err := errors.Join(err1, err2); err != nil {
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
	m.flushLegacy()
	if err := m.checkAnchors(masquerades(plan)); err != nil {
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

func masquerades(plan Plan) bool {
	for _, r := range plan.Rules {
		if r.Masquerade {
			return true
		}
	}
	return false
}
