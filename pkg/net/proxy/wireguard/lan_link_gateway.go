package wireguard

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/peerrendezvous"
)

const (
	publicRefreshInterval = 5 * time.Minute
	publicRetryInterval   = 15 * time.Second
)

// LANLinkGateway owns everything a LAN Link inbound needs: the rendezvous
// coordinator, one WireGuard peer per client, and the public endpoint. All of
// them share the single UDP socket passed to NewLANLinkGateway.
type LANLinkGateway struct {
	hub     *peerrendezvous.Hub
	handler netapi.Handler

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu          sync.Mutex
	config      contract.LANLinkGateway
	links       map[string]*gatewayLink
	refresh     chan struct{}
	publicError string
	closed      bool
}

type gatewayLink struct {
	spec string
	link *managedLink
	key  [32]byte
}

func (*LANLinkGateway) Interface() string { return transport.LANLinkType }

// NewLANLinkGateway takes ownership of socket.
func NewLANLinkGateway(cfg contract.LANLinkGateway, socket net.PacketConn, handler netapi.Handler) (*LANLinkGateway, error) {
	if handler == nil {
		_ = socket.Close()
		return nil, errors.New("LAN Link gateway requires an inbound handler")
	}
	if err := cfg.Validate(); err != nil {
		_ = socket.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &LANLinkGateway{
		hub: peerrendezvous.NewHub(socket), handler: handler, ctx: ctx, cancel: cancel,
		links: make(map[string]*gatewayLink), refresh: make(chan struct{}, 1),
	}
	g.wg.Go(g.maintainPublic)
	if err := g.Apply(cfg); err != nil {
		_ = g.Close()
		return nil, err
	}
	return g, nil
}

func (g *LANLinkGateway) ListenAddr() string { return g.hub.LocalAddr().String() }

func (g *LANLinkGateway) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	links := g.links
	g.links = nil
	g.mu.Unlock()
	g.cancel()
	var wg sync.WaitGroup
	for _, l := range links {
		wg.Go(func() { _ = l.link.Close() })
	}
	wg.Wait()
	err := g.hub.Close()
	g.wg.Wait()
	return err
}

func linkSpec(cfg contract.LANLinkGateway, c contract.LANLinkClient) string {
	return strings.Join([]string{c.Token, c.Registration, fmt.Sprint(c.Slot), cfg.Subnet, cfg.PrivateKey, strings.Join(cfg.Networks, ",")}, "|")
}

// Apply reconciles clients with cfg. Clients whose credentials, address and
// shared networks are unchanged keep their session.
func (g *LANLinkGateway) Apply(cfg contract.LANLinkGateway) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return net.ErrClosed
	}
	next := make(map[string]*gatewayLink, len(cfg.Clients))
	var created []*gatewayLink
	rollback := func() {
		for _, l := range created {
			_ = l.link.Close()
			g.hub.Remove(l.key)
		}
	}
	for _, client := range cfg.Clients {
		spec := linkSpec(cfg, client)
		if existing := g.links[client.ID]; existing != nil && existing.spec == spec {
			next[client.ID] = existing
			continue
		}
		l, err := g.newLink(cfg, client, spec)
		if err != nil {
			rollback()
			return err
		}
		created = append(created, l)
		next[client.ID] = l
	}
	var blocked []string
	for _, client := range cfg.Clients {
		if client.Blocked {
			blocked = append(blocked, client.PairingID())
		}
	}
	g.hub.SetBlocked(blocked)
	for id, old := range g.links {
		if next[id] != old {
			// Closing before replacement frees the pairing's hub slot first.
			_ = old.link.Close()
			if next[id] == nil {
				g.hub.Remove(old.key)
			}
		}
	}
	for _, l := range created {
		l.link.start()
	}
	changed := g.config.PublicEndpoint != cfg.PublicEndpoint || g.config.STUNServer != cfg.STUNServer || g.config.Networks == nil
	g.links, g.config = next, cfg
	if changed {
		select {
		case g.refresh <- struct{}{}:
		default:
		}
	}
	return nil
}

func (g *LANLinkGateway) newLink(cfg contract.LANLinkGateway, client contract.LANLinkClient, spec string) (*gatewayLink, error) {
	key, err := transport.DecodePeerKey(client.Registration)
	if err != nil {
		return nil, err
	}
	server, address, err := cfg.Addresses(client.Slot)
	if err != nil {
		return nil, err
	}
	link, err := newManagedLink(transport.LANLinkInvitation{
		Coordinator: "gateway.invalid:1", Registration: client.Registration, Token: client.Token,
	}, cfg.PrivateKey, g.hub, peerrendezvous.LinkOffer{PublisherIP: server, ClientIP: address, Routes: cfg.Networks}, g.handler)
	if err != nil {
		return nil, err
	}
	return &gatewayLink{spec: spec, link: link, key: key}, nil
}

// Clients reports the live state of every pairing, keyed by pairing ID.
func (g *LANLinkGateway) Clients() map[string]peerrendezvous.PairStatus { return g.hub.Pairs() }

// Links reports the data path of every client session, keyed by client ID.
func (g *LANLinkGateway) Links() map[string]transport.LANLinkStatus {
	g.mu.Lock()
	links := make(map[string]*managedLink, len(g.links))
	for id, l := range g.links {
		links[id] = l.link
	}
	g.mu.Unlock()
	result := make(map[string]transport.LANLinkStatus, len(links))
	for id, link := range links {
		result[id] = link.LANLinkStatus()
	}
	return result
}

func (g *LANLinkGateway) Kick(pairingID string) error {
	id, err := hexDecode16(pairingID)
	if err != nil {
		return err
	}
	return g.hub.Kick(id)
}

// Public returns the endpoint clients use to reach this gateway.
func (g *LANLinkGateway) Public() (string, error) {
	g.mu.Lock()
	cfg, perr := g.config, g.publicError
	g.mu.Unlock()
	if cfg.PublicEndpoint != "" {
		return cfg.PublicEndpoint, nil
	}
	if ap := g.hub.Public(); ap.IsValid() {
		return ap.String(), nil
	}
	if perr == "" {
		perr = "the public endpoint has not been detected yet"
	}
	return "", errors.New(perr)
}

func (g *LANLinkGateway) PublicError() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.publicError
}

func (g *LANLinkGateway) maintainPublic() {
	for {
		delay := publicRefreshInterval
		if err := g.refreshPublic(); err != nil {
			delay = publicRetryInterval
			g.mu.Lock()
			g.publicError = err.Error()
			g.mu.Unlock()
			log.Warn("LAN Link public endpoint", "err", err)
		} else {
			g.mu.Lock()
			g.publicError = ""
			g.mu.Unlock()
		}
		select {
		case <-g.ctx.Done():
			return
		case <-g.refresh:
		case <-time.After(delay):
		}
	}
}

func (g *LANLinkGateway) refreshPublic() error {
	g.mu.Lock()
	cfg := g.config
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
	defer cancel()
	var endpoint netip.AddrPort
	if cfg.PublicEndpoint != "" {
		candidates, err := peerrendezvous.ResolveCoordinators(ctx, cfg.PublicEndpoint)
		if err != nil {
			return fmt.Errorf("resolve public endpoint: %w", err)
		}
		endpoint = candidates[0]
	} else {
		if cfg.Networks == nil {
			return errors.New("LAN Link is not configured yet")
		}
		servers, err := peerrendezvous.ResolveCoordinators(ctx, cfg.STUNAddress())
		if err != nil {
			return fmt.Errorf("resolve STUN server: %w", err)
		}
		var failure error
		for _, server := range servers {
			endpoint, err = g.hub.DiscoverPublic(server, 3*time.Second)
			if err == nil {
				break
			}
			failure = errors.Join(failure, err)
		}
		if !endpoint.IsValid() {
			return fmt.Errorf("could not detect the public endpoint with STUN; set it manually: %w", failure)
		}
	}
	return g.setPublic(endpoint)
}

func (g *LANLinkGateway) setPublic(endpoint netip.AddrPort) error {
	previous := g.hub.Public()
	g.hub.SetPublic(endpoint)
	if previous.IsValid() && previous.Addr().BitLen() != endpoint.Addr().BitLen() {
		// Pairing sockets are bound to an address family; rebuild them.
		g.mu.Lock()
		cfg := g.config
		for id, l := range g.links {
			_ = l.link.Close()
			delete(g.links, id)
		}
		g.mu.Unlock()
		return g.Apply(cfg)
	}
	return nil
}

// Invitation builds the invitation for client using the current public endpoint.
func (g *LANLinkGateway) Invitation(client contract.LANLinkClient) (string, error) {
	public, err := g.Public()
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	networks := slices.Clone(g.config.Networks)
	g.mu.Unlock()
	return (transport.LANLinkInvitation{Coordinator: public, Registration: client.Registration, Token: client.Token, Routes: networks}).Encode()
}

func hexDecode16(s string) ([16]byte, error) {
	var id [16]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 16 {
		return id, errors.New("invalid pairing ID")
	}
	return [16]byte(raw), nil
}
