package inbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

type modeProvider struct{}

func (modeProvider) Verifier(string, string, []string) proxyauth.Verifier {
	return func(ctx context.Context, username string, proof []byte) (*proxyauth.Identity, error) {
		if username != "alice" || string(proof) != "user-secret" {
			return nil, proxyauth.ErrUnauthorized
		}
		return &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: ctx}, nil
	}
}

func TestInboundAuthenticationModesHTTP(t *testing.T) {
	for _, mode := range []string{"legacy", "users", "mixed", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			auth := &contract.Authentication{Mode: mode}
			if mode != "legacy" {
				auth.Users = []string{"alice"}
			}
			config := contract.Inbound{ID: "entry", Authentication: auth, Network: contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPTCPOnly}), Protocol: contract.NewTypedProtocol(contract.HTTPProtocol{Username: "shared", Password: "shared-secret"})}
			handler := netapi.NewChannelHandler(t.Context())
			server, err := listenContract(config, handler, [2]netip.Prefix{}, modeProvider{})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			binding := server.(interface {
				listenerBindings() []contract.RuntimeListener
			}).listenerBindings()[0].Listen
			for _, credential := range []string{"", "shared:shared-secret", "alice:user-secret", "alice:wrong"} {
				conn, err := net.DialTimeout("tcp", binding, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				header := ""
				if credential != "" {
					header = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(credential)) + "\r\n"
				}
				if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n%s\r\n", header); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
				if err != nil {
					t.Fatal(err)
				}
				allowed := credential == "shared:shared-secret" && mode != "users" || credential == "alice:user-secret" && mode != "legacy"
				if (response.StatusCode == 200) != allowed {
					t.Fatalf("mode=%q credential case=%q status=%d", mode, credential[:min(len(credential), 5)], response.StatusCode)
				}
				if allowed {
					select {
					case meta := <-handler.Stream():
						if (meta.Identity != nil) != (credential == "alice:user-secret") {
							t.Fatal("shared traffic acquired user identity")
						}
						_ = meta.Src.Close()
					case <-time.After(time.Second):
						t.Fatal("authenticated stream missing")
					}
				}
				_ = response.Body.Close()
				_ = conn.Close()
			}
			if config.Protocol.HTTP.Password != "shared-secret" {
				t.Fatal("listener startup mutated saved credentials")
			}
		})
	}
}

func TestUserOnlyStripsEverySupportedSharedCredential(t *testing.T) {
	for _, protocol := range []contract.Protocol{
		contract.NewTypedProtocol(contract.HTTPProtocol{Username: "shared", Password: "secret"}),
		contract.NewTypedProtocol(contract.Socks5Protocol{Username: "shared", Password: "secret"}),
		contract.NewTypedProtocol(contract.MixedProtocol{Username: "shared", Password: "secret"}),
		contract.NewTypedProtocol(contract.YuubinsyaProtocol{Password: "secret"}),
		contract.NewTypedProtocol(contract.Hysteria2Protocol{Auth: "secret"}),
	} {
		t.Run(protocol.Type, func(t *testing.T) {
			clean := withoutLegacyAuthentication(protocol)
			switch clean.Type {
			case contract.ProtocolHTTP:
				if clean.HTTP.Username != "" || clean.HTTP.Password != "" || protocol.HTTP.Password != "secret" {
					t.Fatal("HTTP shared credential retained or saved value changed")
				}
			case contract.ProtocolSocks5:
				if clean.Socks5.Username != "" || clean.Socks5.Password != "" || protocol.Socks5.Password != "secret" {
					t.Fatal("SOCKS shared credential retained or saved value changed")
				}
			case contract.ProtocolMixed:
				if clean.Mixed.Username != "" || clean.Mixed.Password != "" || protocol.Mixed.Password != "secret" {
					t.Fatal("Mixed shared credential retained or saved value changed")
				}
			case contract.ProtocolYuubinsya:
				if clean.Yuubinsya.Password != "" || protocol.Yuubinsya.Password != "secret" {
					t.Fatal("Yuubinsya shared credential retained or saved value changed")
				}
			case contract.ProtocolHysteria2:
				if clean.Hysteria2.Auth != "" || protocol.Hysteria2.Auth != "secret" {
					t.Fatal("Hysteria shared credential retained or saved value changed")
				}
			}
		})
	}
}

func TestUserAuthenticationRequiresInstalledProvider(t *testing.T) {
	config := contract.Inbound{ID: "entry", Enabled: true, Authentication: &contract.Authentication{Users: []string{"alice"}}, Network: contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPTCPOnly}), Protocol: contract.NewTypedProtocol(contract.HTTPProtocol{})}
	if server, err := listenContract(config, netapi.NewChannelHandler(t.Context()), [2]netip.Prefix{}); err == nil {
		_ = server.Close()
		t.Fatal("missing identity module admitted user authentication")
	}
	config.Authentication = nil
	server, err := listenContract(config, netapi.NewChannelHandler(t.Context()), [2]netip.Prefix{})
	if err != nil {
		t.Fatalf("legacy listener requires identity module: %v", err)
	}
	_ = server.Close()
}
