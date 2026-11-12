package inbound

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"slices"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type lanLinkAccepter struct {
	linkPublisher
	config contract.Inbound
}

type linkPublisher interface {
	netapi.Accepter
	SetClients([]contract.LANLinkClient) error
}

func listenLANLink(config contract.Inbound, handler netapi.Handler) (netapi.Accepter, error) {
	publisher, err := wireguard.NewLANLinkPublisher(*config.Protocol.LANLink, handler)
	if err != nil {
		return nil, err
	}
	return &lanLinkAccepter{linkPublisher: publisher, config: config}, nil
}

func (s *lanLinkAccepter) ReconfigureContract(next contract.Inbound) (bool, error) {
	if next.Protocol.LANLink == nil {
		return false, nil
	}
	current := s.config
	link := *current.Protocol.LANLink
	link.Clients = next.Protocol.LANLink.Clients
	current.Protocol.LANLink = &link
	if !reflect.DeepEqual(current, next) {
		return false, nil
	}
	if err := s.SetClients(link.Clients); err != nil {
		return true, err
	}
	s.config = next
	return true, nil
}

func (s *ContractStore) CreateLANLinkInvitation(ctx context.Context, id string) (contract.LANLinkInvitationResponse, error) {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if c, managed := secret.FromContext(ctx); managed && (!c.Reveal || !c.Manage) {
		return contract.LANLinkInvitationResponse{}, secret.ErrManage
	}
	config, err := s.store.Get(ctx, id)
	if err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	publisher := config.Protocol.LANLink
	if publisher == nil {
		return contract.LANLinkInvitationResponse{}, errors.New("inbound is not a LAN Link gateway")
	}
	client, err := publisher.AddClient()
	if err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	authority, err := transport.DecodePeerKey(publisher.Registration)
	if err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	clientID, err := client.InvitationID()
	if err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	key, err := transport.LANLinkRegistrationKey(authority, clientID)
	if err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	invitation, err := (transport.LANLinkInvitation{
		Coordinator:  publisher.Coordinator,
		Registration: base64.StdEncoding.EncodeToString(key[:]),
		Token:        client.Token,
		Routes:       publisher.Routes,
	}).Encode()
	if err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	_, addr, err := publisher.Addresses(client.Slot)
	if err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	if err := s.saveLANLinkClients(ctx, config); err != nil {
		return contract.LANLinkInvitationResponse{}, err
	}
	return contract.LANLinkInvitationResponse{Invitation: invitation, ClientID: client.ID, Address: addr.String()}, nil
}

func (s *ContractStore) RevokeLANLinkClient(ctx context.Context, request contract.LANLinkClientRequest) error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	config, err := s.store.Get(ctx, request.ID)
	if err != nil {
		return err
	}
	publisher := config.Protocol.LANLink
	if publisher == nil {
		return errors.New("inbound is not a LAN Link gateway")
	}
	index := slices.IndexFunc(publisher.Clients, func(client contract.LANLinkClient) bool { return client.ID == request.ClientID })
	if index < 0 {
		return plainstore.ErrNotFound
	}
	publisher.Clients = slices.Delete(publisher.Clients, index, index+1)
	return s.saveLANLinkClients(ctx, config)
}

func (s *ContractStore) saveLANLinkClients(ctx context.Context, config contract.Inbound) error {
	if err := s.store.Save(secret.WithResolvedConfiguration(ctx), config, time.Now().Unix()); err != nil {
		return err
	}
	return s.runtime.SaveContract(config)
}

func (l *Inbound) PeerTunnelProtocol(id string) string {
	entry, ok := l.store.Load(id)
	if !ok || entry.contractConfig == nil {
		return ""
	}
	switch entry.contractConfig.Protocol.Type {
	case contract.ProtocolLANLink, contract.ProtocolPeerTunnel:
		return entry.contractConfig.Protocol.Type
	default:
		return ""
	}
}
