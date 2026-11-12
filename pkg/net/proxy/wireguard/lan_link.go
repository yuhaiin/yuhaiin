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

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
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
		return newManagedLink(invite, c.PrivateKey, nil, peerrendezvous.LinkOffer{}, nil)
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
	enrollment   *peerrendezvous.Enrollment
	assignment   peerrendezvous.LinkOffer
	handler      netapi.Handler

	ctx       context.Context
	cancel    context.CancelFunc
	runOnce   sync.Once
	done      chan struct{}
	mu        sync.Mutex
	active    *peerDialer
	changed   chan struct{}
	lastError error
}

func newManagedLink(invite transport.LANLinkInvitation, privateKey string, enrollment *peerrendezvous.Enrollment, assignment peerrendezvous.LinkOffer, handler netapi.Handler) (*managedLink, error) {
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
		registration: registration, token: token, enrollment: enrollment, assignment: assignment, handler: handler,
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
	m.runOnce.Do(func() { go m.run() })
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

func (m *managedLink) update(peer *peerDialer, err error) {
	m.mu.Lock()
	m.active, m.lastError = peer, err
	close(m.changed)
	m.changed = make(chan struct{})
	m.mu.Unlock()
}

func (m *managedLink) run() {
	defer close(m.done)
	for m.ctx.Err() == nil {
		session, err := m.connect()
		if err == nil {
			m.update(session.peer, nil)
			m.waitForAssignmentChange(session.exchange, session.offer)
			m.update(nil, nil)
			if session.flows != nil {
				_ = session.flows.Close()
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
				!slices.Equal(next.Routes, offer.Routes) {
				return
			}
		}
	}
}

type lanLinkSession struct {
	peer     *peerDialer
	flows    netapi.Accepter
	exchange *peerrendezvous.LinkExchange
	offer    peerrendezvous.LinkOffer
}

func (m *managedLink) connect() (*lanLinkSession, error) {
	role := peerrendezvous.Dialer
	if m.enrollment != nil {
		role = peerrendezvous.Publisher
	}
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	underlay, err := newPeerUnderlay(ctx, m.address, m.registration, role)
	cancel()
	var offer peerrendezvous.LinkOffer
	if err != nil {
		return nil, err
	}
	exchange, err := peerrendezvous.NewLinkExchange(m.token, role, m.publicKey, m.assignment)
	if err != nil {
		return nil, err
	}
	underlay.enrollment, underlay.exchange = m.enrollment, exchange
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

	local, remote, routes := offer.ClientIP, offer.PublisherIP, offer.Routes
	if role == peerrendezvous.Publisher {
		local, remote, routes = m.assignment.PublisherIP, m.assignment.ClientIP, m.assignment.Routes
	}
	cfg := transport.PeerTunnel{
		Coordinator: m.address, Token: base64.StdEncoding.EncodeToString(m.registration[:]),
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
	if err := cfg.Validate(); err != nil {
		_ = socket.Close()
		return nil, err
	}
	allowed := cfg.Routes
	if role == peerrendezvous.Publisher {
		allowed = []string{fmt.Sprintf("%s/%d", remote, remote.BitLen())}
	}
	w, err := newClient(Config{
		SecretKey: cfg.PrivateKey, Endpoint: []string{cfg.LocalIP}, MTU: 1280,
		Peers: []PeerConfig{{PublicKey: cfg.PeerPublicKey, Endpoint: bind.openAddr.Load().String(), AllowedIPs: allowed}},
	}, bind, role == peerrendezvous.Publisher)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	var flows netapi.Accepter
	if role == peerrendezvous.Publisher {
		prefixes, err := ParseEndpoints(routes)
		if err == nil {
			flows, err = lightweighttun.NewFromStack(w.net.Stack(), peerRouteFilter{Handler: m.handler, routes: prefixes}, nil, transport.LANLinkType)
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
		_ = socket.Close()
		_ = w.Close()
		return nil, err
	}
	if role == peerrendezvous.Dialer {
		prefixes, _ := transport.ParseLANLinkRoutes(routes)
		m.routes.Store(&prefixes)
	}
	return &lanLinkSession{peer: &peerDialer{Wireguard: w}, flows: flows, exchange: exchange, offer: offer}, nil
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

type lanLinkPublisher struct {
	config    contract.LANLinkPublisher
	handler   netapi.Handler
	authority [32]byte
	links     map[contract.LANLinkClient]*managedLink
}

func (*lanLinkPublisher) Interface() string { return transport.LANLinkType }

func (p *lanLinkPublisher) Close() error {
	var wg sync.WaitGroup
	for _, link := range p.links {
		wg.Go(func() { _ = link.Close() })
	}
	wg.Wait()
	return nil
}

func NewLANLinkPublisher(cfg contract.LANLinkPublisher, handler netapi.Handler) (*lanLinkPublisher, error) {
	if handler == nil {
		return nil, errors.New("LAN Link gateway requires an inbound handler")
	}
	authority, err := transport.DecodePeerKey(cfg.Registration)
	if err != nil {
		return nil, err
	}
	p := &lanLinkPublisher{config: cfg, handler: handler, authority: authority}
	if err := p.SetClients(cfg.Clients); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *lanLinkPublisher) SetClients(clients []contract.LANLinkClient) error {
	cfg := p.config
	cfg.Clients = clients
	if err := cfg.Validate(); err != nil {
		return err
	}
	next := make(map[contract.LANLinkClient]*managedLink, len(clients))
	for _, client := range clients {
		link := p.links[client]
		if link == nil {
			var err error
			link, err = p.newClient(client)
			if err != nil {
				for config, created := range next {
					if p.links[config] == nil {
						_ = created.Close()
					}
				}
				return err
			}
		}
		next[client] = link
	}
	for config, existing := range p.links {
		if next[config] == nil {
			_ = existing.Close()
		}
	}
	p.links = next
	for _, link := range p.links {
		link.start()
	}
	return nil
}

func (p *lanLinkPublisher) newClient(client contract.LANLinkClient) (*managedLink, error) {
	id, err := client.InvitationID()
	if err != nil {
		return nil, err
	}
	key, err := transport.LANLinkRegistrationKey(p.authority, id)
	if err != nil {
		return nil, err
	}
	server, address, err := p.config.Addresses(client.Slot)
	if err != nil {
		return nil, err
	}
	return newManagedLink(transport.LANLinkInvitation{
		Coordinator: p.config.Coordinator, Registration: base64.StdEncoding.EncodeToString(key[:]), Token: client.Token,
	}, p.config.PrivateKey, &peerrendezvous.Enrollment{Authority: p.authority, InvitationID: id},
		peerrendezvous.LinkOffer{PublisherIP: server, ClientIP: address, Routes: p.config.Routes}, p.handler)
}
