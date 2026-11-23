//go:build linux && !android

package sshserver

import (
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	gossh "golang.org/x/crypto/ssh"
)

func BenchmarkSSHServerNetworkReuse(b *testing.B) {
	requireSSHSessionIntegration(b)

	for _, scenario := range []struct {
		name         string
		newTransport bool
		keepNetwork  bool
	}{
		{name: "NewTransport", newTransport: true},
		{name: "SameTransportNewNetwork"},
		{name: "ConcurrentSessionSharedNetwork", keepNetwork: true},
	} {
		b.Run(scenario.name, func(b *testing.B) {
			config, userSigner := newSSHServerTestIdentity(b)
			server := startSSHServerTestServer(b, config, newSSHServerTestHandler())

			var client *gossh.Client
			if !scenario.newTransport {
				var err error
				client, err = newSSHServerClient(server, config.Username, userSigner)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = client.Close() })
			}
			if scenario.keepNetwork {
				keeper, _, stopKeeper := startSSHNamespaceKeeper(b, client)
				b.Cleanup(func() {
					stopKeeper()
					_ = keeper.Wait()
					_ = keeper.Close()
				})
			}

			b.ReportAllocs()
			fds, goroutines := openFDs(), runtime.NumGoroutine()
			b.ResetTimer()
			for b.Loop() {
				if scenario.newTransport {
					var err error
					client, err = newSSHServerClient(server, config.Username, userSigner)
					if err != nil {
						b.Fatal(err)
					}
				}
				session, err := client.NewSession()
				if err == nil {
					err = session.Run("true")
					_ = session.Close()
				}
				if scenario.newTransport {
					_ = client.Close()
				}
				if err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			// Steady-state resources must not grow with the iteration count.
			b.ReportMetric(float64(openFDs()-fds), "fd-delta")
			b.ReportMetric(float64(runtime.NumGoroutine()-goroutines), "goroutine-delta")
		})
	}
}

// BenchmarkSSHServerParallelTransports opens n transports at once, each
// creating its own session namespaces, as simultaneous logins do.
func BenchmarkSSHServerParallelTransports(b *testing.B) {
	requireSSHSessionIntegration(b)
	for _, n := range []int{4, 8} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			config, userSigner := newSSHServerTestIdentity(b)
			config.MaxSessions = 16
			server := startSSHServerTestServer(b, config, newSSHServerTestHandler())
			b.ReportAllocs()
			for b.Loop() {
				var wg sync.WaitGroup
				errs := make(chan error, n)
				for range n {
					wg.Go(func() {
						client, err := newSSHServerClient(server, config.Username, userSigner)
						if err != nil {
							errs <- err
							return
						}
						defer client.Close()
						session, err := client.NewSession()
						if err == nil {
							err = session.Run("true")
							_ = session.Close()
						}
						errs <- err
					})
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					if err != nil {
						b.Fatal(err)
					}
				}
			}
			b.ReportMetric(float64(b.Elapsed().Microseconds())/float64(b.N*n), "µs/transport")
		})
	}
}

func openFDs() int {
	entries, _ := os.ReadDir("/proc/self/fd")
	return len(entries)
}

var _ netapi.Handler = (*sshServerTestHandler)(nil)
