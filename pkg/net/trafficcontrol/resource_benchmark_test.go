package trafficcontrol

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

func benchmarkResourceConfig() resource.Config {
	p := Profile{Upload: Rate{BytesPerSecond: 1 << 40, BurstBytes: 1 << 30}, Download: Rate{BytesPerSecond: 1 << 40, BurstBytes: 1 << 30}}
	return resource.Config{Enabled: true, DefaultUser: resource.Policy{Profile: p, Limits: resource.Limits{MaxSessions: 128}}, Groups: []resource.GroupPolicy{{GroupID: "finance", SharedProfile: p}}}
}

// Loopback plaintext echo exercises the established wrapper in both directions.
// Quotas include asynchronous grant/checkpoint scheduling through a memory
// store, isolating forwarding from filesystem latency. This is not a WAN test.
func BenchmarkResourceTCPForwarding(b *testing.B) {
	for _, mode := range []string{"Absent", "Resources", "Quotas"} {
		b.Run(mode, func(b *testing.B) {
			l := quota.New(initialQuotaStore{})
			defer l.Close(context.Background())
			m := NewManagerWithQuotas(l)
			if mode != "Absent" {
				config := benchmarkResourceConfig()
				if mode == "Quotas" {
					config.DefaultUser.Quotas = []resource.Quota{{ID: "month", Period: "monthly", Combined: "9223372036854775807", Action: "block_new"}}
				}
				if err := m.ApplyResources(config, []IdentityBinding{{UserID: "alice", CredentialID: "phone", GroupIDs: []string{"finance"}}}); err != nil {
					b.Fatal(err)
				}
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer listener.Close()
			peerDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					peerDone <- err
					return
				}
				defer conn.Close()
				_, err = io.Copy(conn, conn)
				peerDone <- err
			}()
			raw, err := new(net.Dialer).DialContext(b.Context(), "tcp", listener.Addr().String())
			if err != nil {
				b.Fatal(err)
			}
			defer raw.Close()
			identity := &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: b.Context()}
			policy := m.ResolveAuthenticated("entry", "", identity)
			conn := WrapConn(b.Context(), raw, func() Policy { return policy })
			readDone := make(chan error, 1)
			go func() { _, err := io.Copy(io.Discard, conn); readDone <- err }()
			payload := make([]byte, 16384)
			b.SetBytes(int64(2 * len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := conn.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
			b.StartTimer()
			if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				b.Fatal(err)
			}
			if err := <-readDone; err != nil {
				b.Fatal(err)
			}
			if err := <-peerDone; err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
		})
	}
}

func BenchmarkResourceAdmission(b *testing.B) {
	m := NewManager()
	if err := m.ApplyResources(benchmarkResourceConfig(), []IdentityBinding{{UserID: "alice", CredentialID: "phone", GroupIDs: []string{"finance"}}}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		lease, ok := m.AcquireResourceSession("alice", "phone", false)
		if !ok {
			b.Fatal("unexpected admission failure")
		}
		lease.Release()
	}
}

func BenchmarkResourceIdleMemory1024(b *testing.B) {
	m := NewManager()
	bindings := make([]IdentityBinding, 1024)
	for i := range bindings {
		bindings[i] = IdentityBinding{UserID: fmt.Sprint(i), CredentialID: fmt.Sprint(i), GroupIDs: []string{"finance"}}
	}
	if err := m.ApplyResources(benchmarkResourceConfig(), bindings); err != nil {
		b.Fatal(err)
	}
	var retained uint64
	for b.Loop() {
		leases := make([]*ResourceSession, len(bindings))
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i, binding := range bindings {
			lease, ok := m.AcquireResourceSession(binding.UserID, binding.CredentialID, false)
			if !ok {
				b.Fatal("unexpected admission failure")
			}
			leases[i] = lease
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		if after.HeapAlloc > before.HeapAlloc {
			retained += after.HeapAlloc - before.HeapAlloc
		}
		runtime.KeepAlive(leases)
		for _, lease := range leases {
			lease.Release()
		}
	}
	b.ReportMetric(float64(retained)/float64(b.N*1024), "heap-B/session")
}

func BenchmarkResourceUpdateUnderTraffic1024(b *testing.B) {
	m := NewManager()
	bindings := make([]IdentityBinding, 1024)
	policies := make([]Policy, len(bindings))
	config := benchmarkResourceConfig()
	for i := range bindings {
		bindings[i] = IdentityBinding{UserID: fmt.Sprint(i), CredentialID: fmt.Sprint(i), GroupIDs: []string{"finance"}}
	}
	if err := m.ApplyResources(config, bindings); err != nil {
		b.Fatal(err)
	}
	for i, binding := range bindings {
		policies[i] = m.ResolveIdentity("entry", "", binding.UserID, binding.CredentialID)
	}
	var stop atomic.Bool
	var checks atomic.Uint64
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			var n uint64
			defer func() { checks.Add(n) }()
			for !stop.Load() {
				for i := worker; i < len(policies); i += 4 {
					policies[i].AllowDatagram(Upload, 1)
					n++
				}
			}
		})
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := m.ApplyResources(config, bindings); err != nil {
			b.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	b.ReportMetric(float64(checks.Load())/b.Elapsed().Seconds(), "concurrent-checks/s")
}
