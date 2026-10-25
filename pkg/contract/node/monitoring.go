package node

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// MonitoringConfig is persisted once per instance. Nil selector overrides
// inherit these values; an explicit disabled override stops that selector's
// demand for shared tasks. Scheduling is opt-in on every platform.
type MonitoringConfig struct {
	Revision uint64        `json:"revision"`
	Probe    ProbeSchedule `json:"probe"`
	Speed    SpeedSchedule `json:"speed"`
}

type ProbeSchedule struct {
	Enabled           bool     `json:"enabled"`
	IntervalMS        int64    `json:"intervalMs,omitzero"`
	TimeoutMS         int64    `json:"timeoutMs,omitzero"`
	Concurrency       int      `json:"concurrency,omitzero"`
	FailureThreshold  int      `json:"failureThreshold,omitzero"`
	RecoveryThreshold int      `json:"recoveryThreshold,omitzero"`
	CooldownMS        int64    `json:"cooldownMs,omitzero"`
	Jitter            float64  `json:"jitter,omitzero"`
	LatencyTarget     string   `json:"latencyTarget,omitempty"`
	TCPAddress        string   `json:"tcpAddress,omitempty"`
	DNSAddress        string   `json:"dnsAddress,omitempty"`
	DNSDomain         string   `json:"dnsDomain,omitempty"`
	STUNAddress       string   `json:"stunAddress,omitempty"`
	Kinds             []string `json:"kinds,omitempty"`
	MaxProbeBandwidth int64    `json:"maxProbeBandwidth,omitzero"`
	NetworkCostPolicy string   `json:"networkCostPolicy,omitempty"`
	AllowMobile       bool     `json:"allowMobile,omitzero"`
}

type SpeedSchedule struct {
	AllowMetered bool             `json:"allowMetered,omitzero"`
	Enabled      bool             `json:"enabled"`
	IntervalMS   int64            `json:"intervalMs,omitzero"`
	Concurrency  int              `json:"concurrency,omitzero"`
	AllowMobile  bool             `json:"allowMobile,omitzero"`
	Test         SpeedTestRequest `json:"test"`
}

// Network state is supplied by native clients or an administrator; defaults
// are online/unmetered, with mobile foreground false. It is runtime-only:
// restarting Android never silently resumes foreground-only background tests.
type MonitoringNetworkState struct {
	Online     bool   `json:"online"`
	Metered    bool   `json:"metered"`
	Foreground bool   `json:"foreground"`
	Generation uint64 `json:"generation"`
}

type MonitoringStatus struct {
	PolicyState string                 `json:"policyState"`
	Config      MonitoringConfig       `json:"config"`
	Network     MonitoringNetworkState `json:"network"`
	Platform    string                 `json:"platform"`
	Jobs        int                    `json:"jobs"`
	Running     int                    `json:"running"`
	Workers     int                    `json:"workers"`
	Completed   uint64                 `json:"completed"`
	Skipped     uint64                 `json:"skipped"`
	Failed      uint64                 `json:"failed"`
}

func (p ProbeSchedule) Effective() ProbeSchedule {
	if p.IntervalMS == 0 {
		p.IntervalMS = 60_000
	}
	if p.TimeoutMS == 0 {
		p.TimeoutMS = 5000
	}
	if p.Concurrency == 0 {
		p.Concurrency = 4
	}
	if p.FailureThreshold == 0 {
		p.FailureThreshold = 3
	}
	if p.RecoveryThreshold == 0 {
		p.RecoveryThreshold = 2
	}
	if p.CooldownMS == 0 {
		p.CooldownMS = 30_000
	}
	if p.LatencyTarget == "" {
		p.LatencyTarget = "https://www.gstatic.com/generate_204"
	}
	if p.TCPAddress == "" {
		p.TCPAddress = "1.1.1.1:443"
	}
	if p.DNSAddress == "" {
		p.DNSAddress = "223.5.5.5:53"
	}
	if p.DNSDomain == "" {
		p.DNSDomain = "www.google.com"
	}
	if p.STUNAddress == "" {
		p.STUNAddress = "stun.nextcloud.com:3478"
	}
	if len(p.Kinds) == 0 {
		p.Kinds = []string{"https", "dns"}
	}
	if p.MaxProbeBandwidth == 0 {
		p.MaxProbeBandwidth = 65536
	}
	if p.NetworkCostPolicy == "" {
		p.NetworkCostPolicy = "conservative"
	}
	return p
}
func (p ProbeSchedule) Validate() error {
	p = p.Effective()
	if p.IntervalMS < 5000 || p.IntervalMS > 86_400_000 || p.TimeoutMS < 100 || p.TimeoutMS > 30_000 || p.Concurrency < 1 || p.Concurrency > 16 || p.FailureThreshold < 1 || p.FailureThreshold > 64 || p.RecoveryThreshold < 1 || p.RecoveryThreshold > 64 || p.CooldownMS < 1000 || p.CooldownMS > 86_400_000 || p.MaxProbeBandwidth < 4096 || p.MaxProbeBandwidth > 16<<20 || math.IsNaN(p.Jitter) || math.IsInf(p.Jitter, 0) || p.Jitter < 0 || p.Jitter > .5 {
		return errors.New("probe timing, concurrency, threshold, jitter or bandwidth out of range")
	}
	if p.NetworkCostPolicy != "conservative" && p.NetworkCostPolicy != "cached_only" && p.NetworkCostPolicy != "allow_expensive" {
		return errors.New("unknown network cost policy")
	}
	if err := validateHTTPSProbeURL(p.LatencyTarget); err != nil {
		return err
	}
	for _, address := range []string{p.TCPAddress, p.DNSAddress, p.STUNAddress} {
		if err := validateProbeAddress(address); err != nil {
			return fmt.Errorf("probe address must be host:port: %w", err)
		}
	}
	if !validProbeDomain(p.DNSDomain) || len(p.Kinds) > 6 {
		return errors.New("invalid DNS domain or probe kinds")
	}
	for _, kind := range p.Kinds {
		if !slices.Contains([]string{"tcp_connect", "https", "dns", "udp", "stun", "native"}, kind) {
			return errors.New("unsupported scheduled probe kind")
		}
	}
	return nil
}
func (s SpeedSchedule) Effective() SpeedSchedule {
	if s.IntervalMS == 0 {
		s.IntervalMS = 3_600_000
	}
	if s.Concurrency == 0 {
		s.Concurrency = 1
	}
	return s
}
func (s SpeedSchedule) Validate() error {
	s = s.Effective()
	if s.IntervalMS < 300_000 || s.IntervalMS > 7*86_400_000 || s.Concurrency < 1 || s.Concurrency > 2 {
		return errors.New("speed schedule interval or concurrency out of range")
	}
	if s.Enabled {
		return s.Test.Validate()
	}
	return nil
}
func validateHTTPSProbeURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(raw) > 2048 {
		return errors.New("probe target requires HTTPS without credentials or fragment")
	}
	return nil
}
func (c MonitoringConfig) Effective() MonitoringConfig {
	c.Probe = c.Probe.Effective()
	c.Speed = c.Speed.Effective()
	return c
}
func (c MonitoringConfig) Validate() error {
	return errors.Join(c.Probe.Validate(), c.Speed.Validate())
}

func validateProbeAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || host == "" {
		return errors.New("invalid host or port")
	}
	return nil
}
func validProbeDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	domain = strings.TrimSuffix(domain, ".")
	for part := range strings.SplitSeq(domain, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}
