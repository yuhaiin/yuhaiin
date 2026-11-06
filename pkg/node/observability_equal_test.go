package node

import (
	"reflect"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func sampleNodeTotals() nodeTotals {
	return nodeTotals{
		ThroughputHistory: []contract.ThroughputMeasurement{{At: 1, OK: true, DownloadMbps: 10}, {At: 2, Target: "t"}},
		TCPHealth:         contract.ChannelHealth{Sequence: 3, State: "healthy", Samples: []contract.HealthSample{{Sequence: 1, At: 1, OK: true, RTTMS: 12, Kind: "tcp"}}},
		UDPHealth:         contract.ChannelHealth{State: "unknown", LatencySamples: []contract.HealthSample{{At: 2, Kind: "udp"}}},
		UploadThroughput:  contract.ThroughputMeasurement{At: 3, UploadMbps: 1},
		Throughput:        contract.ThroughputMeasurement{At: 4, DownloadMbps: 2},
		UploadBytes:       1, DownloadBytes: 2, UDPSentPackets: 3, UDPRecvPackets: 4,
		TCPAttempts: 5, TCPConnections: 6, UDPAttempts: 7, UDPSessions: 8,
		PingAttempts: 9, Failures: 10, LastSuccessAt: 11, LastFailureAt: 12, LastUsedAt: 13,
		LastError: "boom",
		Probes: map[string]contract.ProbeStatus{
			"tcp":  {CheckedAt: 1, Result: contract.LatencyResponse{OK: true, LatencyMS: 5, IP: &contract.IPLatency{IPv4: "1.1.1.1"}}},
			"stun": {CheckedAt: 2, Result: contract.LatencyResponse{STUN: &contract.STUNLatency{Mapping: "eim"}}},
		},
	}
}

func cloneNodeTotals(v nodeTotals) nodeTotals {
	c := v
	c.ThroughputHistory = append([]contract.ThroughputMeasurement(nil), v.ThroughputHistory...)
	c.TCPHealth = copyHealth(v.TCPHealth)
	c.UDPHealth = copyHealth(v.UDPHealth)
	c.Probes = make(map[string]contract.ProbeStatus, len(v.Probes))
	for k, p := range v.Probes {
		if p.Result.IP != nil {
			ip := *p.Result.IP
			p.Result.IP = &ip
		}
		if p.Result.STUN != nil {
			s := *p.Result.STUN
			p.Result.STUN = &s
		}
		c.Probes[k] = p
	}
	return c
}

func TestNodeTotalsEqualMatchesDeepEqual(t *testing.T) {
	base := sampleNodeTotals()
	if same := cloneNodeTotals(base); !base.equal(&same) || !reflect.DeepEqual(base, same) {
		t.Fatal("deep copy compared unequal")
	}
	mutations := map[string]func(*nodeTotals){
		"ThroughputHistory": func(v *nodeTotals) { v.ThroughputHistory[1].Error = "x" },
		"TCPHealth":         func(v *nodeTotals) { v.TCPHealth.Samples[0].RTTMS = 13 },
		"UDPHealth":         func(v *nodeTotals) { v.UDPHealth.LatencySamples = nil },
		"UploadThroughput":  func(v *nodeTotals) { v.UploadThroughput.Samples = 1 },
		"Throughput":        func(v *nodeTotals) { v.Throughput.OK = true },
		"UploadBytes":       func(v *nodeTotals) { v.UploadBytes++ },
		"DownloadBytes":     func(v *nodeTotals) { v.DownloadBytes++ },
		"UDPSentPackets":    func(v *nodeTotals) { v.UDPSentPackets++ },
		"UDPRecvPackets":    func(v *nodeTotals) { v.UDPRecvPackets++ },
		"TCPAttempts":       func(v *nodeTotals) { v.TCPAttempts++ },
		"TCPConnections":    func(v *nodeTotals) { v.TCPConnections++ },
		"UDPAttempts":       func(v *nodeTotals) { v.UDPAttempts++ },
		"UDPSessions":       func(v *nodeTotals) { v.UDPSessions++ },
		"PingAttempts":      func(v *nodeTotals) { v.PingAttempts++ },
		"Failures":          func(v *nodeTotals) { v.Failures++ },
		"LastSuccessAt":     func(v *nodeTotals) { v.LastSuccessAt++ },
		"LastFailureAt":     func(v *nodeTotals) { v.LastFailureAt++ },
		"LastUsedAt":        func(v *nodeTotals) { v.LastUsedAt++ },
		"LastError":         func(v *nodeTotals) { v.LastError = "" },
		"Probes":            func(v *nodeTotals) { p := v.Probes["tcp"]; p.Result.IP.IPv4 = "8.8.8.8"; v.Probes["tcp"] = p },
	}
	// A new nodeTotals field must be added to equal and to this table.
	if n := reflect.TypeFor[nodeTotals]().NumField(); n != len(mutations) {
		t.Fatalf("nodeTotals has %d fields, equality table covers %d", n, len(mutations))
	}
	for name, mutate := range mutations {
		v := cloneNodeTotals(base)
		mutate(&v)
		if base.equal(&v) || v.equal(&base) {
			t.Errorf("%s change not detected", name)
		}
	}
	extra := cloneNodeTotals(base)
	extra.Probes["udp"] = contract.ProbeStatus{}
	if base.equal(&extra) {
		t.Error("added probe not detected")
	}
}

func benchmarkNodeSnapshots(n int) ([]nodeTotals, []nodeTotals) {
	saved, current := make([]nodeTotals, n), make([]nodeTotals, n)
	for i := range saved {
		saved[i] = sampleNodeTotals()
		current[i] = cloneNodeTotals(saved[i])
	}
	return saved, current
}

func BenchmarkNodeTotalsUnchanged(b *testing.B) {
	saved, current := benchmarkNodeSnapshots(100)
	b.Run("DeepEqual", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for i := range saved {
				if !reflect.DeepEqual(saved[i], current[i]) {
					b.Fatal("unequal")
				}
			}
		}
	})
	b.Run("Typed", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for i := range saved {
				if !saved[i].equal(&current[i]) {
					b.Fatal("unequal")
				}
			}
		}
	})
}
