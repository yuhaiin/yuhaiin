package inbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	accesscontract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	rule "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/accesscontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/route"
)

type accessIntegrationProvider map[string]*proxyauth.Identity

func (p accessIntegrationProvider) Verifier(string, string, []string) proxyauth.Verifier {
	return func(_ context.Context, user string, proof []byte) (*proxyauth.Identity, error) {
		if identity := p[user]; identity != nil && string(proof) == "test-proof" {
			return identity, nil
		}
		return nil, proxyauth.ErrUnauthorized
	}
}

type accessIntegrationDialer struct{}

func (accessIntegrationDialer) GetTarget(_ context.Context, _, mode string, _ rule.Target) (netapi.Proxy, error) {
	if mode == "block" {
		return netapi.NewErrProxy(netapi.ErrTrafficAccessDenied), nil
	}
	return direct.Default, nil
}

type accessIntegrationResolver struct{ netapi.Resolver }

func (r accessIntegrationResolver) Get(string, string) netapi.Resolver { return r }

func TestAuthenticatedHTTPForwardingPolicyRevocationAndLegacyIsolation(t *testing.T) {
	peer, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := peer.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	access := accesscontrol.New()
	defer access.Close()
	group := func(name string) accesscontract.Rule {
		return accesscontract.Rule{ID: name, Action: "allow", Conditions: []rule.RuleExpr{{Type: "group", Group: &rule.IdentityExpr{IDs: []string{name}}}}}
	}
	activate := func(finance bool) {
		t.Helper()
		cfg := accesscontract.Config{Enabled: true, Scope: accesscontract.Scope{AllInbounds: true}, DefaultAction: "deny", Rules: []accesscontract.Rule{group("engineering")}}
		if finance {
			cfg.Rules = append(cfg.Rules, group("finance"))
		}
		p, err := accesscontrol.Prepare(cfg)
		if err != nil {
			t.Fatal(err)
		}
		access.Activate(p)
	}
	activate(true)
	lists := route.NewLists(nil, nil, t.TempDir())
	defer lists.Close()
	router := route.NewRoute(accessIntegrationDialer{}, accessIntegrationResolver{}, lists, nil)
	router.SetTrafficAccess(access)
	provider := accessIntegrationProvider{}
	for user, group := range map[string]string{"alice": "finance", "bob": "engineering", "charlie": "guest"} {
		provider[user] = &proxyauth.Identity{UserID: user, CredentialID: user + "-phone", GroupIDs: []string{group}, Context: t.Context()}
	}
	inbound := NewInbound(router, WithAuthentication(provider), WithTrafficAccess(access))
	defer inbound.Close()
	cfg := contract.Inbound{ID: "entry", Name: "Enterprise", Enabled: true, Authentication: &contract.Authentication{Mode: "mixed", Users: []string{"alice", "bob", "charlie"}}, Network: contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPTCPOnly}), Protocol: contract.NewTypedProtocol(contract.HTTPProtocol{Username: "shared", Password: "legacy-proof"})}
	if err := inbound.SaveContract(cfg); err != nil {
		t.Fatal(err)
	}
	entry, _ := inbound.store.Load("entry")
	binding := entry.server.(interface {
		listenerBindings() []contract.RuntimeListener
	}).listenerBindings()[0].Listen
	connect := func(credential string) (net.Conn, *bufio.Reader) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", binding, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		proof := base64.StdEncoding.EncodeToString([]byte(credential))
		if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", peer.Addr(), peer.Addr(), proof); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if err != nil || response.StatusCode != 200 {
			t.Fatal("authentication handshake", response, err)
		}
		return conn, reader
	}
	echo := func(conn net.Conn, reader *bufio.Reader) {
		t.Helper()
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(reader, buf); err != nil || string(buf) != "hello" {
			t.Fatal("authorized forwarding", string(buf), err)
		}
	}
	closed := func(conn net.Conn, reader *bufio.Reader) {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := reader.ReadByte()
		if err == nil {
			t.Fatal("unauthorized bytes forwarded")
		}
		if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
			t.Fatal("authorization failed to close the tunnel", err)
		}
	}
	alice, aliceReader := connect("alice:test-proof")
	echo(alice, aliceReader)
	bob, bobReader := connect("bob:test-proof")
	echo(bob, bobReader)
	for _, credential := range []string{"charlie:test-proof", "shared:legacy-proof"} {
		conn, reader := connect(credential)
		_, _ = conn.Write([]byte("must not reach peer"))
		closed(conn, reader)
	}
	if accepted.Load() != 2 {
		t.Fatal("unauthorized transport reached the upstream", accepted.Load())
	}
	activate(false)
	closed(alice, aliceReader)
	echo(bob, bobReader)
	_ = alice.Close()
	_ = bob.Close()
}
