package inbound

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/peerrendezvous"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

// lanLinkAccepter is a LAN Link gateway as an inbound: one UDP socket serves
// the coordinator and every client's tunnel.
type lanLinkAccepter struct {
	*wireguard.LANLinkGateway
	config contract.Inbound
}

func listenLANLink(config contract.Inbound, handler netapi.Handler) (netapi.Accepter, error) {
	gateway := config.Protocol.LANLink
	socket, err := dialer.ListenPacket(context.Background(), "udp", gateway.ListenAddress(), dialer.WithListener())
	if err != nil {
		return nil, err
	}
	g, err := wireguard.NewLANLinkGateway(*gateway, socket, handler)
	if err != nil {
		return nil, err
	}
	return &lanLinkAccepter{LANLinkGateway: g, config: config}, nil
}

func (s *lanLinkAccepter) listenerBindings() []contract.RuntimeListener {
	return []contract.RuntimeListener{{Kind: "udp", Listen: s.ListenAddr()}}
}

// ReconfigureContract applies client, network and public endpoint changes to
// the running gateway. Anything that needs a new socket restarts the inbound.
func (s *lanLinkAccepter) ReconfigureContract(next contract.Inbound) (bool, error) {
	if next.Protocol.LANLink == nil {
		return false, nil
	}
	current := s.config
	link := *current.Protocol.LANLink
	n := next.Protocol.LANLink
	link.Networks, link.Subnet, link.Clients = n.Networks, n.Subnet, n.Clients
	link.PublicEndpoint, link.STUNServer = n.PublicEndpoint, n.STUNServer
	current.Protocol.LANLink = &link
	if !reflect.DeepEqual(current, next) {
		return false, nil
	}
	if err := s.Apply(*n); err != nil {
		return true, err
	}
	s.config = next
	return true, nil
}

func (s *ContractStore) lanLinkGateway(id string) *lanLinkAccepter {
	entry, _ := s.runtime.store.Load(id)
	server, _ := entry.server.(*lanLinkAccepter)
	return server
}

// lanLinkConfig loads an inbound that must be a LAN Link gateway.
func (s *ContractStore) lanLinkConfig(ctx context.Context, id string) (contract.Inbound, *contract.LANLinkGateway, error) {
	config, err := s.store.Get(ctx, id)
	if err != nil {
		return contract.Inbound{}, nil, err
	}
	if config.Protocol.LANLink == nil {
		return contract.Inbound{}, nil, errors.New("inbound is not a LAN Link gateway")
	}
	return config, config.Protocol.LANLink, nil
}

func (s *ContractStore) CreateLANLinkInvitation(ctx context.Context, request contract.LANLinkInvitationRequest) (contract.LANLinkInvitationResponse, error) {
	id := request.ID
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if c, managed := secret.FromContext(ctx); managed && (!c.Reveal || !c.Manage) {
		return contract.LANLinkInvitationResponse{}, secret.ErrManage
	}
	config, gateway, err := s.lanLinkConfig(ctx, id)
	if err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	running := s.lanLinkGateway(id)
	if running == nil {
		return contract.LANLinkInvitationResponse{}, errors.New("enable the LAN Link gateway before generating an invitation")
	}
	client, err := gateway.AddClient(time.Now().Unix(), request.Name)
	if err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	// Build the invitation before saving so an unknown public endpoint leaves
	// no half-created client behind.
	invitation, err := running.Invitation(client)
	if err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	_, addr, err := gateway.Addresses(client.Slot)
	if err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	if err := s.saveLANLinkConfig(ctx, config); err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	return contract.LANLinkInvitationResponse{Invitation: invitation, ClientID: client.ID, Name: client.Name, Address: addr.String()}, nil
}

// RevokeLANLinkClient deletes a client. Its tunnel is closed before this
// returns, and its invitation can never register again.
func (s *ContractStore) RevokeLANLinkClient(ctx context.Context, request contract.LANLinkClientRequest) error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	config, gateway, err := s.lanLinkConfig(ctx, request.ID)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(gateway.Clients, func(c contract.LANLinkClient) bool { return c.ID == request.ClientID })
	if index < 0 {
		return plainstore.ErrNotFound
	}
	gateway.Clients = slices.Delete(gateway.Clients, index, index+1)
	return s.saveLANLinkConfig(ctx, config)
}

func (s *ContractStore) LANLinkClients(ctx context.Context, id string) (contract.LANLinkClients, error) {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	_, gateway, err := s.lanLinkConfig(ctx, id)
	if err != nil {
		return contract.LANLinkClients{}, err
	}
	result := contract.LANLinkClients{Subnet: gateway.Subnet, Items: make([]contract.LANLinkClientStatus, 0, len(gateway.Clients))}
	running := s.lanLinkGateway(id)
	var live map[string]peerrendezvous.PairStatus
	if running != nil {
		live = running.Clients()
		result.Running = true
		result.PublicEndpoint, _ = running.Public()
		result.PublicError = running.PublicError()
	}
	for _, client := range gateway.Clients {
		_, address, _ := gateway.Addresses(client.Slot)
		item := contract.LANLinkClientStatus{
			ID: client.ID, Name: client.Name, Address: address.String(), PairingID: client.PairingID(),
			Blocked: client.Blocked, CreatedAt: client.CreatedAt,
		}
		state := live[item.PairingID]
		item.DialerEndpoint, item.PublisherEndpoint = endpointString(state.Dialer), endpointString(state.Publisher)
		item.Online = state.Dialer.IsValid() && !client.Blocked
		if state.Dialer.IsValid() {
			item.Path = transport.LANLinkPathKind(state.Dialer.Addr(), false)
		}
		if !state.KickUntil.IsZero() {
			item.RetryAt = state.KickUntil.UnixMilli()
			item.Online = false
		}
		result.Items = append(result.Items, item)
	}
	return result, nil
}

func (s *ContractStore) UpdateLANLinkClient(ctx context.Context, request contract.LANLinkClientAction) error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	config, gateway, err := s.lanLinkConfig(ctx, request.ID)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(gateway.Clients, func(c contract.LANLinkClient) bool { return c.ID == request.ClientID })
	if index < 0 {
		return plainstore.ErrNotFound
	}
	client := &gateway.Clients[index]
	switch request.Action {
	case "kick":
		running := s.lanLinkGateway(request.ID)
		if running == nil {
			return errors.New("LAN Link gateway is inactive")
		}
		if client.Blocked {
			return errors.New("LAN Link client is blocked")
		}
		return running.Kick(client.PairingID())
	case "block", "unblock":
		client.Blocked = request.Action == "block"
		return s.saveLANLinkConfig(ctx, config)
	case "rename":
		name, err := contract.NormalizeLANLinkClientName(request.Name)
		if err != nil {
			return err
		}
		client.Name = name
		return s.saveLANLinkConfig(ctx, config)
	default:
		return errors.New("unknown LAN Link client action")
	}
}

func (s *ContractStore) LANLinkNetworks(context.Context) contract.LANLinkNetworks {
	return detectLANLinkNetworks()
}

func (s *ContractStore) saveLANLinkConfig(ctx context.Context, config contract.Inbound) error {
	if err := s.store.Save(secret.WithResolvedConfiguration(ctx), config, time.Now().Unix()); err != nil {
		return err
	}
	return s.runtime.SaveContract(config)
}

// LANLinkInbound reports whether the inbound is a LAN Link gateway.
func (l *Inbound) LANLinkInbound(id string) bool {
	entry, ok := l.store.Load(id)
	return ok && entry.contractConfig != nil && entry.contractConfig.Protocol.Type == contract.ProtocolLANLink
}

func endpointString(addr netip.AddrPort) string {
	if addr.IsValid() {
		return addr.String()
	}
	return ""
}
