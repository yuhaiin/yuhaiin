package wireguard

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
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
	routes       atomic.Pointer[[]netip.Prefix]
	address      string
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
	// localIP and peerIP are the tunnel addresses of the active session.
	localIP, peerIP netip.Addr
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
		address: invite.Coordinator, privateKey: privateKey, publicKey: [32]byte(private.PublicKey().Bytes()),
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

func (m *managedLink) NodeExtraInfo() contractnode.NodeExtraInfo {
	return contractnode.NodeExtraInfo{LANLink: new(m.status())}
}

// status reports the live pairing state without starting the link.
func (m *managedLink) status() transport.LANLinkStatus {
	status := transport.LANLinkStatus{PairingID: transport.PeerPairIDString(m.registration), State: "idle", Coordinator: m.address}
	if !m.started.Load() {
		return status
	}
	m.mu.Lock()
	peer, lastError, local, remote := m.active, m.lastError, m.localIP, m.peerIP
	m.mu.Unlock()
	status.State = "connecting"
	if lastError != nil {
		status.Error = lastError.Error()
	}
	if peer == nil {
		return status
	}
	status.LocalIP, status.PeerIP = local.String(), remote.String()
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
	m.active, m.lastError, m.localIP, m.peerIP = nil, err, netip.Addr{}, netip.Addr{}
	if session != nil {
		m.active, m.localIP, m.peerIP = session.peer, session.localIP, session.peerIP
	}
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
			if next.PublisherIP != offer.PublisherIP || next.ClientIP != offer.ClientIP ||
				!slices.Equal(next.Routes, offer.Routes) || next.Subnet != offer.Subnet {
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
	// localIP and peerIP are this side's and the peer's tunnel addresses.
	localIP, peerIP netip.Addr
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
		underlay, err = newPeerUnderlay(ctx, m.address, m.registration, role)
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

	local, remote, routes, subnetValue := offer.ClientIP, offer.PublisherIP, offer.Routes, offer.Subnet
	if role == peerrendezvous.Publisher {
		local, remote, routes, subnetValue = m.assignment.PublisherIP, m.assignment.ClientIP, m.assignment.Routes, m.assignment.Subnet
	}
	cfg := tunnelConfig{
		PrivateKey: m.privateKey, PeerPublicKey: base64.StdEncoding.EncodeToString(offer.PublicKey[:]),
		LocalIP: local.String(), PeerIP: remote.String(), Routes: routes,
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
	subnet, err := parseLANLinkSubnet(subnetValue, local, remote, routes)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	allowed := cfg.Routes
	if role == peerrendezvous.Publisher {
		allowed = []string{fmt.Sprintf("%s/%d", remote, remote.BitLen())}
	} else if subnet.IsValid() {
		allowed = append(slices.Clone(allowed), subnet.String())
	}
	incoming := role == peerrendezvous.Publisher || (subnet.IsValid() && m.allowIncoming)
	w, err := newClient(Config{
		SecretKey: cfg.PrivateKey, Endpoint: []string{cfg.LocalIP}, MTU: 1280,
		Peers: []PeerConfig{{PublicKey: cfg.PeerPublicKey, Endpoint: bind.openAddr.Load().String(), AllowedIPs: allowed}},
	}, bind, incoming)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	var flows netapi.Accepter
	var dispatch *lanLinkFlows
	if incoming {
		spec := lanLinkFlowSpec{peer: remote, subnet: subnet}
		if role == peerrendezvous.Publisher {
			spec.handler, spec.relay = m.handler, m.relay
			spec.routes, err = ParseEndpoints(routes)
		}
		if subnet.IsValid() {
			// Client-to-client mode makes this side's own address reachable.
			spec.local = local
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
		if subnet.IsValid() {
			prefixes = append(prefixes, subnet)
		}
		m.routes.Store(&prefixes)
	}
	return &lanLinkSession{peer: &peerDialer{Wireguard: w}, flows: flows, dispatch: dispatch, exchange: exchange, offer: offer, localIP: local, peerIP: remote}, nil
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

// parseLANLinkSubnet validates the tunnel network of a client-to-client
// assignment. An empty value disables client-to-client traffic.
func parseLANLinkSubnet(value string, local, remote netip.Addr, routes []string) (netip.Prefix, error) {
	if value == "" {
		return netip.Prefix{}, nil
	}
	subnet, err := netip.ParsePrefix(value)
	if err != nil || subnet != subnet.Masked() || subnet.Addr().BitLen() != local.BitLen() ||
		!subnet.Contains(local) || !subnet.Contains(remote) {
		return netip.Prefix{}, fmt.Errorf("LAN Link: invalid tunnel subnet %q", value)
	}
	for _, route := range routes {
		if p, err := netip.ParsePrefix(route); err == nil && p.Overlaps(subnet) {
			return netip.Prefix{}, fmt.Errorf("LAN Link: tunnel subnet %q overlaps route %q", value, route)
		}
	}
	return subnet, nil
}
