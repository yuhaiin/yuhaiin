//go:build linux && !android

package sshserver

import (
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	gossh "golang.org/x/crypto/ssh"
)

func BenchmarkSSHServerNetworkReuse(b *testing.B) {
	if os.Getenv(sshIntegrationEnv) != "1" {
		b.Skip("set " + sshIntegrationEnv + "=1 on a Linux host with TUN and network namespace privileges")
	}

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
				keeper, _ := startSSHNamespaceKeeper(b, client)
				b.Cleanup(func() {
					_ = keeper.Close()
					_ = keeper.Wait()
				})
			}

			b.ReportAllocs()
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
		})
	}
}

var _ netapi.Handler = (*sshServerTestHandler)(nil)
