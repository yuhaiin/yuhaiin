package system

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

func IsTailscaleIP(ip netip.Addr) bool {
	// TODO
	return false
}

// An OSConfigurator applies DNS settings to the operating system.
type OSConfigurator interface {
	// SetDNS updates the OS's DNS configuration to match cfg.
	// If cfg is the zero value, all Tailscale-related DNS
	// configuration is removed.
	// SetDNS must not be called after Close.
	// SetDNS takes ownership of cfg.
	SetDNS(cfg OSConfig) error
	// SupportsSplitDNS reports whether the configurator is capable of
	// installing a resolver only for specific DNS suffixes. If false,
	// the configurator can only set a global resolver.
	SupportsSplitDNS() bool
	// GetBaseConfig returns the OS's "base" configuration, i.e. the
	// resolver settings the OS would use without Tailscale
	// contributing any configuration.
	// GetBaseConfig must return the tailscale-free base config even
	// after SetDNS has been called to set a Tailscale configuration.
	// Only works when SupportsSplitDNS=false.

	// Implementations that don't support getting the base config must
	// return ErrGetBaseConfigNotSupported.
	GetBaseConfig() (OSConfig, error)
	// Close removes Tailscale-related DNS configuration from the OS.
	Close() error
}

// HostEntry represents a single line in the OS's hosts file.
type HostEntry struct {
	Addr  netip.Addr
	Hosts []string
}

// A FQDN is a fully-qualified DNS name or name suffix.
type FQDN string

const (
	// maxLabelLength is the maximum length of a label permitted by RFC 1035.
	maxLabelLength = 63
	// maxNameLength is the maximum length of a DNS name.
	maxNameLength = 253
)

func ToFQDN(s string) (FQDN, error) {
	if len(s) == 0 || s == "." {
		return FQDN("."), nil
	}

	if s[0] == '.' {
		s = s[1:]
	}
	raw := s
	totalLen := len(s)
	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	} else {
		totalLen += 1 // account for missing dot
	}
	if totalLen > maxNameLength {
		return "", fmt.Errorf("%q is too long to be a DNS name", s)
	}

	st := 0
	for i := range len(s) {
		if s[i] != '.' {
			continue
		}
		label := s[st:i]
		// You might be tempted to do further validation of the
		// contents of labels here, based on the hostname rules in RFC
		// 1123. However, DNS labels are not always subject to
		// hostname rules. In general, they can contain any non-zero
		// byte sequence, even though in practice a more restricted
		// set is used.
		//
		// See https://github.com/tailscale/tailscale/issues/2024 for more.
		if len(label) == 0 || len(label) > maxLabelLength {
			return "", fmt.Errorf("%q is not a valid DNS label", label)
		}
		st = i + 1
	}

	if raw[len(raw)-1] != '.' {
		raw = raw + "."
	}
	return FQDN(raw), nil
}

// WithTrailingDot returns f as a string, with a trailing dot.
func (f FQDN) WithTrailingDot() string {
	return string(f)
}

// WithoutTrailingDot returns f as a string, with the trailing dot
// removed.
func (f FQDN) WithoutTrailingDot() string {
	return string(f[:len(f)-1])
}

// OSConfig is an OS DNS configuration.
type OSConfig struct {
	// Hosts is a map of DNS FQDNs to their IPs, which should be added to the
	// OS's hosts file. Currently, (2022-08-12) it is only populated for Windows
	// in SplitDNS mode and with Smart Name Resolution turned on.
	Hosts []*HostEntry
	// Nameservers are the IP addresses of the nameservers to use.
	Nameservers []netip.Addr
	// SearchDomains are the domain suffixes to use when expanding
	// single-label name queries. SearchDomains is additive to
	// whatever non-Tailscale search domains the OS has.
	SearchDomains []FQDN
	// MatchDomains are the DNS suffixes for which Nameservers should
	// be used. If empty, Nameservers is installed as the "primary" resolver.
	// A non-empty MatchDomains requests a "split DNS" configuration
	// from the OS, which will only work with OSConfigurators that
	// report SupportsSplitDNS()=true.
	MatchDomains []FQDN
}

func (o *OSConfig) WriteToBufioWriter(w *bufio.Writer) {
	if o == nil {
		w.WriteString("<nil>")
		return
	}
	w.WriteString("{")
	if len(o.Hosts) > 0 {
		fmt.Fprintf(w, "Hosts:%v ", o.Hosts)
	}
	if len(o.Nameservers) > 0 {
		fmt.Fprintf(w, "Nameservers:%v ", o.Nameservers)
	}
	if len(o.SearchDomains) > 0 {
		fmt.Fprintf(w, "SearchDomains:%v ", o.SearchDomains)
	}
	if len(o.MatchDomains) > 0 {
		w.WriteString("MatchDomains:[")
		sp := ""
		var numARPA int
		for _, s := range o.MatchDomains {
			if strings.HasSuffix(string(s), ".arpa.") {
				numARPA++
				continue
			}
			w.WriteString(sp)
			w.WriteString(string(s))
			sp = " "
		}
		w.WriteString("]")
		if numARPA > 0 {
			fmt.Fprintf(w, "+%darpa", numARPA)
		}
	}
	w.WriteString("}")
}

func (o OSConfig) IsZero() bool {
	return len(o.Hosts) == 0 &&
		len(o.Nameservers) == 0 &&
		len(o.SearchDomains) == 0 &&
		len(o.MatchDomains) == 0
}

func (a OSConfig) Equal(b OSConfig) bool {
	if len(a.Hosts) != len(b.Hosts) {
		return false
	}
	if len(a.Nameservers) != len(b.Nameservers) {
		return false
	}
	if len(a.SearchDomains) != len(b.SearchDomains) {
		return false
	}
	if len(a.MatchDomains) != len(b.MatchDomains) {
		return false
	}

	for i := range a.Hosts {
		ha, hb := a.Hosts[i], b.Hosts[i]
		if ha.Addr != hb.Addr {
			return false
		}
		if !slices.Equal(ha.Hosts, hb.Hosts) {
			return false
		}
	}
	for i := range a.Nameservers {
		if a.Nameservers[i] != b.Nameservers[i] {
			return false
		}
	}
	for i := range a.SearchDomains {
		if a.SearchDomains[i] != b.SearchDomains[i] {
			return false
		}
	}
	for i := range a.MatchDomains {
		if a.MatchDomains[i] != b.MatchDomains[i] {
			return false
		}
	}

	return true
}

// ArgWriter is a fmt.Formatter that can be passed to any Logf func to
// efficiently write to a %v argument without allocations.
type ArgWriter func(*bufio.Writer)

func (fn ArgWriter) Format(f fmt.State, _ rune) {
	bw := bufio.NewWriter(f)
	fn(bw)
	bw.Flush()
}

// Format implements the fmt.Formatter interface to ensure that Hosts is
// printed correctly (i.e. not as a bunch of pointers).
//
// Fixes https://github.com/tailscale/tailscale/issues/5669
func (a OSConfig) Format(f fmt.State, verb rune) {
	ArgWriter(func(w *bufio.Writer) {
		w.WriteString(`{Nameservers:[`)
		for i, ns := range a.Nameservers {
			if i != 0 {
				w.WriteString(" ")
			}
			fmt.Fprintf(w, "%+v", ns)
		}
		w.WriteString(`] SearchDomains:[`)
		for i, domain := range a.SearchDomains {
			if i != 0 {
				w.WriteString(" ")
			}
			fmt.Fprintf(w, "%+v", domain)
		}
		w.WriteString(`] MatchDomains:[`)
		for i, domain := range a.MatchDomains {
			if i != 0 {
				w.WriteString(" ")
			}
			fmt.Fprintf(w, "%+v", domain)
		}
		w.WriteString(`] Hosts:[`)
		for i, host := range a.Hosts {
			if i != 0 {
				w.WriteString(" ")
			}
			fmt.Fprintf(w, "%+v", host)
		}
		w.WriteString(`]}`)
	}).Format(f, verb)
}

// ErrGetBaseConfigNotSupported is the error
// OSConfigurator.GetBaseConfig returns when the OSConfigurator
// doesn't support reading the underlying configuration out of the OS.
var ErrGetBaseConfigNotSupported = errors.New("getting OS base config is not supported")
