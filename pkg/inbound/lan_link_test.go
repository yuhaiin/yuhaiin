package inbound

import (
	"context"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

const lanTestNetwork = "192.168.50.0/24"

// lanTestUpstream pretends the shared LAN exists: any address inside it is
// served by a local echo server, and everything else is refused.
type lanTestUpstream struct {
	netapi.Proxy
	network netip.Prefix
	target  string
	udp     string
	dials   atomic.Int32
}

func (u *lanTestUpstream) redirect(addr netapi.Address) (netapi.Address, error) {
	ip, ok := addr.(netapi.IPAddress)
	if !ok || !u.network.Contains(ip.AddrPort().Addr()) {
		return nil, net.UnknownNetworkError("outside the shared LAN")
	}
	if addr.Network() == "udp" {
		return netapi.ParseAddress("udp", u.udp)
	}
	return netapi.ParseAddress("tcp", u.target)
}

func (u *lanTestUpstream) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	real, err := u.redirect(addr)
	if err != nil {
		return nil, err
	}
	u.dials.Add(1)
	return u.Proxy.Conn(ctx, real)
}

func (u *lanTestUpstream) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	real, err := u.redirect(addr)
	if err != nil {
		return nil, err
	}
	pc, err := u.Proxy.PacketConn(ctx, real)
	if err != nil {
		return nil, err
	}
	return &rewritePacketConn{PacketConn: pc, real: real, fake: addr}, nil
}

type rewritePacketConn struct {
	net.PacketConn
	real, fake netapi.Address
}

func (r *rewritePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return r.PacketConn.WriteTo(p, r.real)
}
func (r *rewritePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, err := r.PacketConn.ReadFrom(p)
	return n, r.fake, err
}

func freeUDPPort(t testing.TB) int {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

type lanLinkFixture struct {
	t        testing.TB
	ctx      context.Context
	state    string
	runtime  *Inbound
	store    *ContractStore
	nodes    *node.NodeRuntime
	upstream *lanTestUpstream
	gateway  contract.Inbound
	target   netapi.Address
}

func newLANLinkFixture(t *testing.T) *lanLinkFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)
	f := &lanLinkFixture{t: t, ctx: ctx, state: filepath.Join(t.TempDir(), "state.db")}
	var accepted atomic.Int32
	echo := tcpEcho(t, "127.0.0.1", &accepted)
	f.upstream = &lanTestUpstream{Proxy: direct.Default, network: netip.MustParsePrefix(lanTestNetwork), target: echo.String(), udp: udpEcho(t).String()}
	port := freeUDPPort(t)
	f.target, _ = netapi.ParseAddress("tcp", net.JoinHostPort("192.168.50.10", strconv.Itoa(int(echo.Port()))))
	f.gateway = contract.Inbound{
		ID: "gateway", Name: "Gateway", Enabled: true,
		Network: contract.NewTypedNetwork(contract.EmptyNetwork{}),
		Protocol: contract.NewTypedProtocol(contract.LANLinkGateway{
			Networks: []string{lanTestNetwork}, Listen: "127.0.0.1:" + strconv.Itoa(port),
			PublicEndpoint: "127.0.0.1:" + strconv.Itoa(port),
		}),
	}
	f.start()
	f.nodes = node.NewNodeRuntime(f.state)
	t.Cleanup(func() { _ = f.nodes.Close() })
	return f
}

func (f *lanLinkFixture) start() {
	f.t.Helper()
	db, err := sqlite.Open(f.ctx, f.state)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = db.Close() })
	f.runtime = NewInbound(f.upstream)
	f.t.Cleanup(func() { _ = f.runtime.Close() })
	inbounds := plainstore.NewInboundStore(db.DB())
	if _, err := inbounds.Settings(f.ctx); err != nil {
		if err := inbounds.SaveSettings(f.ctx, plainstore.InboundSettings{}); err != nil {
			f.t.Fatal(err)
		}
	}
	f.store = NewContractStore(inbounds, f.runtime)
	if err := f.store.Sync(f.ctx); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.store.Get(f.ctx, f.gateway.ID); err != nil {
		if err := f.store.Save(f.ctx, f.gateway, 0); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *lanLinkFixture) invite(id string) (netapi.Proxy, contract.LANLinkInvitationResponse) {
	f.t.Helper()
	var value contract.LANLinkInvitationResponse
	var err error
	for range 40 { // the public endpoint resolves asynchronously after start
		if value, err = f.store.CreateLANLinkInvitation(f.ctx, f.gateway.ID); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return f.importInvitation(id, value.Invitation), value
}

func (f *lanLinkFixture) importInvitation(id, invitation string) netapi.Proxy {
	f.t.Helper()
	protocol, err := contractnode.NewTypedProtocol(transport.LANLink{Invitation: invitation})
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.nodes.Save(f.ctx, contractnode.Node{ID: id, Name: id, Origin: "manual", Enabled: true, Chain: []contractnode.Protocol{protocol}}); err != nil {
		f.t.Fatal(err)
	}
	proxy, err := f.nodes.GetDialerByID(f.ctx, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return proxy
}

func (f *lanLinkFixture) echo(proxy netapi.Proxy, addr netapi.Address) error {
	conn, err := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
		defer cancel()
		return proxy.Conn(ctx, addr)
	}()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("link")); err != nil {
		return err
	}
	var data [4]byte
	if _, err := io.ReadFull(conn, data[:]); err != nil {
		return err
	}
	if string(data[:]) != "link" {
		f.t.Errorf("echo = %q", data)
	}
	return nil
}

func (f *lanLinkFixture) eventually(what string, fn func() error) {
	f.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		if err = fn(); err == nil {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	f.t.Fatalf("%s: %v", what, err)
}

func (f *lanLinkFixture) client(id string) contract.LANLinkClientStatus {
	f.t.Helper()
	list, err := f.store.LANLinkClients(f.ctx, f.gateway.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, item := range list.Items {
		if item.ID == id {
			return item
		}
	}
	f.t.Fatalf("client %s missing from %+v", id, list)
	return contract.LANLinkClientStatus{}
}

// A single inbound starts its own coordinator, issues independent invitations
// and forwards TCP and UDP only inside the shared networks.
func TestLANLinkSingleInboundForwardsAndManagesClients(t *testing.T) {
	f := newLANLinkFixture(t)
	saved, err := f.store.Get(f.ctx, f.gateway.ID)
	if err != nil {
		t.Fatal(err)
	}
	link := saved.Protocol.LANLink
	pool, err := netip.ParsePrefix(link.Subnet)
	if err != nil || !pool.Addr().IsPrivate() || link.PrivateKey == "" {
		t.Fatalf("generated tunnel state: %+v, %v", link, err)
	}
	if listeners := f.runtime.runtimeStatus(saved).Listeners; len(listeners) != 1 || listeners[0].Kind != "udp" {
		t.Fatalf("gateway listeners: %+v", listeners)
	}

	first, firstInvite := f.invite("first")
	if target, ok := f.nodes.LANLinkTarget(f.ctx, netip.MustParseAddr("192.168.50.10")); !ok || target.ID != "first" {
		t.Fatalf("invitation did not install a LAN route: %+v, %v", target, ok)
	}
	f.eventually("first TCP", func() error { return f.echo(first, f.target) })

	second, secondInvite := f.invite("second")
	if firstInvite.Address == secondInvite.Address || !pool.Contains(netip.MustParseAddr(firstInvite.Address)) ||
		!pool.Contains(netip.MustParseAddr(secondInvite.Address)) {
		t.Fatalf("invalid address allocations %s and %s in %s", firstInvite.Address, secondInvite.Address, pool)
	}
	if target, ok := f.nodes.LANLinkTarget(f.ctx, netip.MustParseAddr("192.168.50.10")); !ok || target.ID != "" {
		t.Fatalf("overlapping LAN routes were not reported as ambiguous: %+v, %v", target, ok)
	}
	f.eventually("second TCP", func() error { return f.echo(second, f.target) })

	udp, _ := netapi.ParseAddress("udp", "192.168.50.10:5353")
	datagram, err := second.PacketConn(f.ctx, udp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = datagram.Close() })
	_ = datagram.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := datagram.WriteTo([]byte("lan link"), udp); err != nil {
		t.Fatal(err)
	}
	var udpData [32]byte
	if n, _, err := datagram.ReadFrom(udpData[:]); err != nil || string(udpData[:n]) != "lan link" {
		t.Fatalf("UDP echo: %q, %v", udpData[:n], err)
	}

	// Addresses outside the shared network never reach the upstream.
	outside, _ := netapi.ParseAddress("tcp", "192.168.60.1:80")
	dials := f.upstream.dials.Load()
	if err := f.echo(second, outside); err == nil {
		t.Fatal("a destination outside the shared networks was forwarded")
	}
	if f.upstream.dials.Load() != dials {
		t.Fatal("the gateway dialed a destination outside the shared networks")
	}

	// Client management reports the independent pairings.
	f.eventually("clients online", func() error {
		for _, id := range []string{firstInvite.ClientID, secondInvite.ClientID} {
			if c := f.client(id); !c.Online || c.PairingID == "" || c.Address == "" {
				return net.UnknownNetworkError(id + " offline")
			}
		}
		return nil
	})
	if f.client(firstInvite.ClientID).PairingID == f.client(secondInvite.ClientID).PairingID {
		t.Fatal("clients share a pairing credential")
	}

	// Kick disconnects only the target; it may return after the retry window.
	act := func(id, action string) error {
		return f.store.UpdateLANLinkClient(f.ctx, contract.LANLinkClientAction{ID: f.gateway.ID, ClientID: id, Action: action})
	}
	if err := act(firstInvite.ClientID, "kick"); err != nil {
		t.Fatal(err)
	}
	f.eventually("kick visible", func() error {
		if f.client(firstInvite.ClientID).RetryAt == 0 {
			return net.UnknownNetworkError("not kicked")
		}
		return nil
	})
	if err := f.echo(second, f.target); err != nil {
		t.Fatalf("kicking the first client interrupted the second: %v", err)
	}

	// Block survives until unblocked and does not touch the other client.
	if err := act(firstInvite.ClientID, "block"); err != nil {
		t.Fatal(err)
	}
	if !f.client(firstInvite.ClientID).Blocked || f.client(firstInvite.ClientID).Online {
		t.Fatalf("block state: %+v", f.client(firstInvite.ClientID))
	}
	if err := f.echo(first, f.target); err == nil {
		t.Fatal("blocked client still forwards data")
	}
	if err := f.echo(second, f.target); err != nil {
		t.Fatalf("blocking the first client interrupted the second: %v", err)
	}
	if err := act(firstInvite.ClientID, "unblock"); err != nil {
		t.Fatal(err)
	}

	// Revoke removes the client for good.
	if err := f.store.RevokeLANLinkClient(f.ctx, contract.LANLinkClientRequest{ID: f.gateway.ID, ClientID: firstInvite.ClientID}); err != nil {
		t.Fatal(err)
	}
	if err := f.echo(first, f.target); err == nil {
		t.Fatal("revoked client still forwards data")
	}
	if err := f.echo(second, f.target); err != nil {
		t.Fatalf("revoking the first client interrupted the second: %v", err)
	}

	// Editing the shared networks with a stale editor keeps clients, secrets,
	// and the tunnel subnet; the live client keeps its session.
	stale := saved
	stale.Protocol.LANLink = &contract.LANLinkGateway{Networks: []string{lanTestNetwork, "192.168.70.0/24"},
		Listen: link.Listen, PublicEndpoint: link.PublicEndpoint}
	if err := f.store.Save(f.ctx, stale, 0); err != nil {
		t.Fatal(err)
	}
	current, err := f.store.Get(f.ctx, f.gateway.ID)
	if err != nil {
		t.Fatal(err)
	}
	after := current.Protocol.LANLink
	if after.Subnet != link.Subnet || after.PrivateKey != link.PrivateKey || len(after.Clients) != 1 ||
		after.Clients[0].ID != secondInvite.ClientID || len(after.Networks) != 2 {
		t.Fatalf("network edit lost state: %+v", after)
	}
	f.eventually("second after network edit", func() error { return f.echo(second, f.target) })

	// A restart keeps clients, addresses and credentials; the client reconnects
	// with the invitation it already imported.
	secret := after.Clients[0]
	f.upstream.dials.Store(0)
	if err := f.runtime.Close(); err != nil {
		t.Fatal(err)
	}
	f.start()
	restarted, err := f.store.Get(f.ctx, f.gateway.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.Protocol.LANLink.Clients; len(got) != 1 || got[0] != secret {
		t.Fatalf("restart changed client credentials: %+v", got)
	}
	f.eventually("reconnect after gateway restart", func() error { return f.echo(second, f.target) })
}

func TestLANLinkInvitationNeedsRunningGateway(t *testing.T) {
	f := newLANLinkFixture(t)
	disabled := f.gateway
	disabled.Enabled = false
	if err := f.store.Save(f.ctx, disabled, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateLANLinkInvitation(f.ctx, f.gateway.ID); err == nil {
		t.Fatal("an invitation was issued by an inactive gateway")
	}
	if got, _ := f.store.Get(f.ctx, f.gateway.ID); len(got.Protocol.LANLink.Clients) != 0 {
		t.Fatal("a failed invitation left a client behind")
	}
}
