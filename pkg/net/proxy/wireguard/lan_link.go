package wireguard

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/peerrendezvous"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweighttun"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterContractPoint(transport.LANLinkType, func(c transport.LANLink, _ netapi.Proxy) (netapi.Proxy, error) {
		invite, err := transport.ParseLANLinkInvitation(c.Invitation)
		if err != nil {
			return nil, err
		}
		if c.PrivateKey == "" {
			c.PrivateKey, err = transport.NewLANLinkPrivateKey()
			if err != nil {
				return nil, err
			}
		}
		link, err := newManagedLink(invite, c.PrivateKey, nil, peerrendezvous.LinkOffer{}, nil)
		if err != nil {
			return nil, err
		}
		if link.allowIncoming = c.AllowIncoming; link.allowIncoming {
			// Incoming flows cannot wait for outgoing traffic to start the link.
			link.start()
		}
		return link, nil
	})
}

type managedLink struct {
	netapi.EmptyDispatch
	routes atomic.Pointer[[]netip.Prefix]
	// addresses are the gateway's endpoints, one per IP family.
	addresses    []string
	privateKey   string
	publicKey    [32]byte
	registration [32]byte
	token        [32]byte
	hub          *peerrendezvous.Hub
	assignment   peerrendezvous.LinkOffer
	handler      netapi.Handler
	// relay forwards client-to-client flows on the gateway.
	relay lanLinkRelay
	// allowIncoming delivers flows to this client's tunnel address locally.
	allowIncoming bool

	ctx       context.Context
	cancel    context.CancelFunc
	runOnce   sync.Once
	started   atomic.Bool
	done      chan struct{}
	mu        sync.Mutex
	active    *peerDialer
	changed   chan struct{}
	lastError error
	// localIPs and peerIPs are the tunnel addresses of the active session.
	localIPs, peerIPs []netip.Addr
	// exchange is the active session's provisioning exchange.
	exchange *peerrendezvous.LinkExchange
	// peerList is what a gateway link serves to its client; peers is what a
	// client last received from its gateway.
	peerList []byte
	peers    []transport.LANLinkPeer
	// early holds a peer list that arrived before its session was active.
	early struct {
		exchange *peerrendezvous.LinkExchange
		peers    []transport.LANLinkPeer
	}
}

func newManagedLink(invite transport.LANLinkInvitation, privateKey string, hub *peerrendezvous.Hub, assignment peerrendezvous.LinkOffer, handler netapi.Handler) (*managedLink, error) {
	key, err := transport.DecodePeerKey(privateKey)
	if err != nil {
		return nil, err
	}
	private, err := ecdh.X25519().NewPrivateKey(key[:])
	if err != nil {
		return nil, err
	}
	registration, err := transport.DecodePeerKey(invite.Registration)
	if err != nil {
		return nil, err
	}
	token, err := transport.DecodePeerKey(invite.Token)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &managedLink{
		addresses: invite.CoordinatorList(), privateKey: privateKey, publicKey: [32]byte(private.PublicKey().Bytes()),
		registration: registration, token: token, hub: hub, assignment: assignment, handler: handler,
		ctx: ctx, cancel: cancel, done: make(chan struct{}), changed: make(chan struct{}),
	}, nil
}

// LANLinkRoutes reports the last authenticated route advertisement.
func (m *managedLink) LANLinkRoutes() ([]netip.Prefix, bool) {
	routes := m.routes.Load()
	if routes == nil {
		return nil, false
	}
	return *routes, true
}

func (m *managedLink) start() {
	m.runOnce.Do(func() {
		m.started.Store(true)
		go m.run()
	})
}

// AutoConnect starts the link without waiting for traffic. It keeps
// reconnecting until closed.
func (m *managedLink) AutoConnect(context.Context) error {
	m.start()
	return nil
}

func (m *managedLink) NodeExtraInfo() contractnode.NodeExtraInfo {
	return contractnode.NodeExtraInfo{LANLink: new(m.status())}
}

// status reports the live pairing state without starting the link.
func (m *managedLink) status() transport.LANLinkStatus {
	status := transport.LANLinkStatus{PairingID: transport.PeerPairIDString(m.registration), State: "idle", Coordinator: strings.Join(m.addresses, ", ")}
	if !m.started.Load() {
		return status
	}
	m.mu.Lock()
	peer, lastError, local, remote, peers := m.active, m.lastError, m.localIPs, m.peerIPs, m.peers
	m.mu.Unlock()
	status.State = "connecting"
	if lastError != nil {
		status.Error = lastError.Error()
	}
	if peer == nil {
		return status
	}
	status.LocalIPs, status.PeerIPs, status.Peers = addrStrings(local), addrStrings(remote), slices.Clone(peers)
	active := peer.bind.active.Load()
	if active == nil {
		return status
	}
	socket, ok := active.conn.(*peerrendezvous.Socket)
	if !ok {
		return status
	}
	path := socket.Path()
	if path.Local.IsValid() {
		status.Listen = path.Local.String()
	}
	if path.Peer.IsValid() {
		status.PeerEndpoint = path.Peer.String()
		status.Path = transport.LANLinkPathKind(path.Peer.Addr(), path.OnLink)
		if path.Ready {
			status.State = "connected"
		}
	}
	return status
}

func (m *managedLink) Close() error {
	m.cancel()
	m.start()
	<-m.done
	return nil
}

func (m *managedLink) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	peer, err := m.peer(ctx)
	if err != nil {
		return nil, err
	}
	return peer.Conn(ctx, addr)
}

func (m *managedLink) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	peer, err := m.peer(ctx)
	if err != nil {
		return nil, err
	}
	return peer.PacketConn(ctx, addr)
}

func (*managedLink) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.ErrUnsupported
}

func (m *managedLink) peer(ctx context.Context) (*peerDialer, error) {
	m.start()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		m.mu.Lock()
		peer, changed, lastError := m.active, m.changed, m.lastError
		m.mu.Unlock()
		if peer != nil {
			return peer, nil
		}
		select {
		case <-m.ctx.Done():
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, fmt.Errorf("LAN Link: waiting for an authenticated peer: %w", errors.Join(ctx.Err(), lastError))
		case <-changed:
		}
	}
}

func (m *managedLink) update(session *lanLinkSession, err error) {
	m.mu.Lock()
	m.active, m.lastError, m.localIPs, m.peerIPs, m.exchange, m.peers = nil, err, nil, nil, nil, nil
	if session != nil {
		m.active, m.localIPs, m.peerIPs, m.exchange = session.peer, session.localIPs, session.peerIPs, session.exchange
		if m.early.exchange == session.exchange {
			m.peers = m.early.peers
		}
	}
	m.early.exchange, m.early.peers = nil, nil
	close(m.changed)
	m.changed = make(chan struct{})
	m.mu.Unlock()
}

func (m *managedLink) run() {
	defer close(m.done)
	for m.ctx.Err() == nil {
		session, err := m.connect()
		if err == nil {
			m.update(session, nil)
			m.waitForAssignmentChange(session.exchange, session.offer)
			m.update(nil, nil)
			if session.flows != nil {
				_ = session.flows.Close()
			}
			if session.dispatch != nil {
				session.dispatch.Close()
			}
			_ = session.peer.Close()
			continue
		}
		m.update(nil, err)
		select {
		case <-m.ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

func (m *managedLink) waitForAssignmentChange(exchange *peerrendezvous.LinkExchange, offer peerrendezvous.LinkOffer) {
	for {
		select {
		case <-m.ctx.Done():
			return
		case next := <-exchange.Results():
			if !offer.SameAssignment(next) {
				return
			}
		}
	}
}

type lanLinkSession struct {
	peer     *peerDialer
	flows    netapi.Accepter
	dispatch *lanLinkFlows
	exchange *peerrendezvous.LinkExchange
	offer    peerrendezvous.LinkOffer
	// localIPs and peerIPs are this side's and the peer's tunnel addresses.
	localIPs, peerIPs []netip.Addr
}

// setPeerList sets the peer list a gateway link serves to its client.
func (m *managedLink) setPeerList(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if slices.Equal(m.peerList, data) {
		return
	}
	m.peerList = data
	if m.exchange != nil {
		m.exchange.SetPeers(data)
	}
}

// receivePeers stores the peer list a client received from its gateway.
func (m *managedLink) receivePeers(exchange *peerrendezvous.LinkExchange, data []byte) {
	var peers []transport.LANLinkPeer
	if json.Unmarshal(data, &peers) != nil {
		return
	}
	m.mu.Lock()
	switch {
	case m.exchange == exchange:
		m.peers = peers
	case m.exchange == nil:
		m.early.exchange, m.early.peers = exchange, peers
	}
	m.mu.Unlock()
}

func addrStrings(addrs []netip.Addr) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

func (m *managedLink) connect() (*lanLinkSession, error) {
	role := peerrendezvous.Dialer
	if m.hub != nil {
		role = peerrendezvous.Publisher
	}
	var underlay *peerUnderlay
	if m.hub != nil {
		underlay = &peerUnderlay{key: m.registration, role: role, bind: newNetBindClient(nil), open: func() (net.PacketConn, netip.AddrPort, error) {
			return m.hub.Open(m.registration)
		}}
	} else {
		ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
		var err error
		underlay, err = newPeerUnderlay(ctx, m.addresses, m.registration, role)
		cancel()
		if err != nil {
			return nil, err
		}
		underlay.hosted = true
	}
	var offer peerrendezvous.LinkOffer
	exchange, err := peerrendezvous.NewLinkExchange(m.token, role, m.publicKey, m.assignment)
	if err != nil {
		return nil, err
	}
	underlay.exchange = exchange
	if role == peerrendezvous.Publisher {
		m.mu.Lock()
		if m.peerList != nil {
			exchange.SetPeers(m.peerList)
		}
		m.mu.Unlock()
	} else {
		exchange.OnPeers(func(data []byte) { m.receivePeers(exchange, data) })
	}
	var boot atomic.Pointer[peerrendezvous.Socket]
	var device atomic.Pointer[Wireguard]
	underlay.rebind = func() {
		if w := device.Load(); w != nil {
			w.rebind()
		} else if socket := boot.Load(); socket != nil {
			_ = socket.Close()
		}
	}

	for {
		pc, err := underlay.listen(m.ctx, "udp", "", func(o *dialer.Options) {
			o.PacketConnHintAddress = underlay.bind.openAddr.Load()
			o.OnNetworkInvalidated = underlay.rebind
		})
		if err != nil {
			return nil, err
		}
		socket := pc.(*peerrendezvous.Socket)
		boot.Store(socket)
		offer, err = awaitLinkOffer(m.ctx, socket, exchange)
		if err != nil {
			_ = socket.Close()
			if errors.Is(err, net.ErrClosed) && m.ctx.Err() == nil {
				continue
			}
			return nil, err
		}
		break
	}

	publisherIPs, clientIPs, subnetValues := offer.Tunnel()
	local, remote, routes := clientIPs, publisherIPs, offer.Routes
	if role == peerrendezvous.Publisher {
		publisherIPs, clientIPs, subnetValues = m.assignment.Tunnel()
		local, remote, routes = publisherIPs, clientIPs, m.assignment.Routes
	}
	cfg := tunnelConfig{
		PrivateKey: m.privateKey, PeerPublicKey: base64.StdEncoding.EncodeToString(offer.PublicKey[:]),
		LocalIPs: local, PeerIPs: remote, Routes: routes,
	}
	socket := boot.Load()
	var first atomic.Pointer[peerrendezvous.Socket]
	first.Store(socket)
	bind := underlay.bind
	bind.listenPacket = func(ctx context.Context, network, addr string, opts ...func(*dialer.Options)) (net.PacketConn, error) {
		if socket := first.Swap(nil); socket != nil {
			return socket, nil
		}
		return underlay.listen(ctx, network, addr, opts...)
	}
	if err := cfg.validate(); err != nil {
		_ = socket.Close()
		return nil, err
	}
	subnets, err := parseLANLinkSubnets(subnetValues, local, remote, routes)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	var allowed []string
	if role == peerrendezvous.Publisher {
		for _, ip := range remote {
			allowed = append(allowed, netip.PrefixFrom(ip, ip.BitLen()).String())
		}
	} else {
		allowed = slices.Clone(cfg.Routes)
		for _, subnet := range subnets {
			allowed = append(allowed, subnet.String())
		}
	}
	incoming := role == peerrendezvous.Publisher || (len(subnets) != 0 && m.allowIncoming)
	w, err := newClient(Config{
		SecretKey: cfg.PrivateKey, Endpoint: addrStrings(local), MTU: 1280,
		Peers: []PeerConfig{{PublicKey: cfg.PeerPublicKey, Endpoint: bind.openAddr.Load().String(), AllowedIPs: allowed}},
	}, bind, incoming)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	var flows netapi.Accepter
	var dispatch *lanLinkFlows
	if incoming {
		spec := lanLinkFlowSpec{peers: remote, subnets: subnets}
		if role == peerrendezvous.Publisher {
			spec.handler, spec.relay = m.handler, m.relay
			spec.routes, err = ParseEndpoints(routes)
		}
		if len(subnets) != 0 {
			// Client-to-client mode makes this side's own addresses reachable.
			spec.locals = local
		}
		if err == nil {
			dispatch = newLANLinkFlows(m.ctx, spec)
			flows, err = lightweighttun.NewFromStack(w.net.Stack(), dispatch, nil, transport.LANLinkType)
		}
		if err != nil {
			_ = socket.Close()
			_ = w.Close()
			return nil, err
		}
	}
	device.Store(w)
	if err := w.init(); err != nil {
		if flows != nil {
			_ = flows.Close()
		}
		if dispatch != nil {
			dispatch.Close()
		}
		_ = socket.Close()
		_ = w.Close()
		return nil, err
	}
	if role == peerrendezvous.Dialer {
		prefixes, _ := transport.ParseLANLinkRoutes(routes)
		prefixes = append(prefixes, subnets...)
		m.routes.Store(&prefixes)
	}
	return &lanLinkSession{peer: &peerDialer{Wireguard: w}, flows: flows, dispatch: dispatch, exchange: exchange, offer: offer, localIPs: local, peerIPs: remote}, nil
}

func awaitLinkOffer(ctx context.Context, socket *peerrendezvous.Socket, exchange *peerrendezvous.LinkExchange) (peerrendezvous.LinkOffer, error) {
	var buf [1200]byte
	for {
		select {
		case <-ctx.Done():
			return peerrendezvous.LinkOffer{}, ctx.Err()
		case offer := <-exchange.Results():
			return offer, socket.SetReadDeadline(time.Time{})
		default:
		}
		if err := socket.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return peerrendezvous.LinkOffer{}, err
		}
		if err := socket.ReadControl(buf[:]); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			return peerrendezvous.LinkOffer{}, err
		}
	}
}

// parseLANLinkSubnets validates the tunnel networks of a client-to-client
// assignment: each holds this side's and the peer's address of its family. No
// subnet disables client-to-client traffic.
func parseLANLinkSubnets(values []string, local, remote []netip.Addr, routes []string) ([]netip.Prefix, error) {
	prefixes, err := transport.ParseLANLinkRoutes(routes)
	if err != nil {
		return nil, err
	}
	subnets, err := transport.ParseLANLinkSubnets(values, prefixes)
	if err != nil {
		return nil, err
	}
	for _, subnet := range subnets {
		if !slices.ContainsFunc(local, subnet.Contains) || !slices.ContainsFunc(remote, subnet.Contains) {
			return nil, fmt.Errorf("LAN Link: tunnel subnet %s does not hold both tunnel addresses", subnet)
		}
	}
	return subnets, nil
}
