package wireguard

import (
	"context"
	"encoding/hex"
	json "encoding/json/v2"
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
	// peerListInterval is how often clients' peer lists are refreshed. A list
	// is sent to a client only when it changed.
	peerListInterval = 3 * time.Second
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
	// addresses are the client's tunnel addresses.
	addresses []netip.Addr
	client    contract.LANLinkClient
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
	g.wg.Go(g.maintainPeers)
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
	return strings.Join([]string{c.Token, c.Registration, fmt.Sprint(c.Slot), cfg.Subnet, cfg.Subnet6, cfg.PrivateKey, strings.Join(cfg.Networks, ","), fmt.Sprint(cfg.ClientToClient)}, "|")
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
	g.publishPeersLocked(cfg, next)
	for _, l := range created {
		l.link.start()
	}
	changed := g.config.PublicEndpoint != cfg.PublicEndpoint || g.config.PublicEndpoint6 != cfg.PublicEndpoint6 || g.config.STUNServer != cfg.STUNServer || g.config.Networks == nil
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
	offer, err := gatewayOffer(cfg, server, address)
	if err != nil {
		return nil, err
	}
	link, err := newManagedLink(transport.LANLinkInvitation{
		Coordinator: "gateway.invalid:1", Registration: client.Registration, Token: client.Token,
	}, cfg.PrivateKey, g.hub, offer, g.handler)
	if err != nil {
		return nil, err
	}
	if cfg.ClientToClient {
		link.relay = g
	}
	return &gatewayLink{spec: spec, link: link, key: key, addresses: address, client: client}, nil
}

// gatewayOffer builds a client's assignment. The single-value fields carry the
// family of the first shared network for clients without dual-stack support.
func gatewayOffer(cfg contract.LANLinkGateway, server, client []netip.Addr) (peerrendezvous.LinkOffer, error) {
	routes, err := transport.ParseLANLinkRoutes(cfg.Networks)
	if err != nil {
		return peerrendezvous.LinkOffer{}, err
	}
	pools, err := cfg.TunnelSubnets()
	if err != nil {
		return peerrendezvous.LinkOffer{}, err
	}
	offer := peerrendezvous.LinkOffer{Routes: cfg.Networks, PublisherIPs: server, ClientIPs: client}
	primary := 0
	for i, ip := range server {
		if ip.BitLen() == routes[0].Addr().BitLen() {
			primary = i
		}
	}
	offer.PublisherIP, offer.ClientIP = server[primary], client[primary]
	if cfg.ClientToClient {
		offer.Subnet = pools[primary].String()
		for _, pool := range pools {
			offer.Subnets = append(offer.Subnets, pool.String())
		}
	}
	return offer, nil
}

// relayTarget returns the link of the client that owns the tunnel address to.
func (g *LANLinkGateway) relayTarget(from []netip.Addr, to netip.Addr) (lanLinkDialer, bool) {
	if slices.Contains(from, to) {
		return nil, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.config.ClientToClient {
		return nil, false
	}
	for _, l := range g.links {
		if slices.Contains(l.addresses, to) {
			return l.link, true
		}
	}
	return nil, false
}

func (g *LANLinkGateway) maintainPeers() {
	ticker := time.NewTicker(peerListInterval)
	defer ticker.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case <-ticker.C:
		}
		g.mu.Lock()
		if !g.closed {
			g.publishPeersLocked(g.config, g.links)
		}
		g.mu.Unlock()
	}
}

// publishPeersLocked gives every client the list of the other clients, or an
// empty list when client-to-client traffic is off.
func (g *LANLinkGateway) publishPeersLocked(cfg contract.LANLinkGateway, links map[string]*gatewayLink) {
	pairs := g.hub.Pairs()
	all := make([]transport.LANLinkPeer, 0, len(cfg.Clients))
	owners := make([]string, 0, len(cfg.Clients))
	if cfg.ClientToClient {
		for _, client := range cfg.Clients {
			l := links[client.ID]
			if l == nil || client.Blocked {
				continue
			}
			state := pairs[client.PairingID()]
			all = append(all, transport.LANLinkPeer{
				Name: client.Name, Addresses: addrStrings(l.addresses),
				Online: state.Dialer.IsValid() && state.KickUntil.IsZero(),
			})
			owners = append(owners, client.ID)
		}
	}
	for id, l := range links {
		peers := make([]transport.LANLinkPeer, 0, len(all))
		for i, peer := range all {
			if owners[i] != id {
				peers = append(peers, peer)
			}
		}
		data, err := json.Marshal(peers)
		if err == nil {
			l.link.setPeerList(data)
		}
	}
}

// Clients reports the live state of every pairing, keyed by pairing ID.
func (g *LANLinkGateway) Clients() map[string]peerrendezvous.PairStatus { return g.hub.Pairs() }

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

// refreshPublic finds the gateway's public endpoints: the configured one,
// resolved in every IP family it has, or one per family from STUN. A family
// that STUN cannot reach, such as IPv6 on an IPv4-only host, is skipped.
func (g *LANLinkGateway) refreshPublic() error {
	g.mu.Lock()
	cfg := g.config
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
	defer cancel()
	var endpoints []netip.AddrPort
	if cfg.PublicEndpoint != "" {
		candidates, err := peerrendezvous.ResolveCoordinatorList(ctx, cfg.PublicEndpoints())
		if err != nil {
			return fmt.Errorf("resolve public endpoint: %w", err)
		}
		endpoints = candidates
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
			endpoint, err := g.hub.DiscoverPublic(server, 3*time.Second)
			if err != nil {
				failure = errors.Join(failure, err)
				continue
			}
			endpoints = append(endpoints, endpoint)
		}
		if len(endpoints) == 0 {
			return fmt.Errorf("could not detect the public endpoint with STUN; set it manually: %w", failure)
		}
	}
	g.hub.SetPublic(endpoints...)
	return nil
}

// Publics returns the gateway's public endpoints, IPv4 first.
func (g *LANLinkGateway) Publics() []string {
	var out []string
	for _, endpoint := range g.hub.Publics() {
		out = append(out, endpoint.String())
	}
	return out
}

// Invitation builds the invitation for client using the current public endpoint.
func (g *LANLinkGateway) Invitation(client contract.LANLinkClient) (string, error) {
	public, err := g.Public()
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	invitation := transport.LANLinkInvitation{
		Coordinator: public, Registration: client.Registration, Token: client.Token,
		Routes: slices.Clone(g.config.Networks),
	}
	if g.config.PublicEndpoint == "" {
		// Detected endpoints are addresses; list every family so clients of
		// both can connect.
		if publics := g.Publics(); len(publics) > 1 {
			invitation.Coordinators = publics
		}
	} else if g.config.PublicEndpoint6 != "" {
		// A configured hostname resolves on the client in every family.
		invitation.Coordinators = g.config.PublicEndpoints()
	}
	if g.config.ClientToClient {
		if pools, err := g.config.TunnelSubnets(); err == nil {
			for _, pool := range pools {
				invitation.Subnets = append(invitation.Subnets, pool.String())
			}
			// Clients that predate dual-stack tunnels read only Subnet, in the
			// family of the first route.
			if routes, err := transport.ParseLANLinkRoutes(invitation.Routes); err == nil {
				for _, pool := range pools {
					if pool.Addr().BitLen() == routes[0].Addr().BitLen() {
						invitation.Subnet = pool.String()
					}
				}
			}
		}
	}
	g.mu.Unlock()
	return invitation.Encode()
}

func hexDecode16(s string) ([16]byte, error) {
	var id [16]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 16 {
		return id, errors.New("invalid pairing ID")
	}
	return [16]byte(raw), nil
}
