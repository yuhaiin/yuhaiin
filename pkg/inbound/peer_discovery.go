package inbound

import (
	"context"
	"encoding/hex"
	"errors"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/net/peerrendezvous"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

type discoveryAccepter struct {
	*peerrendezvous.Coordinator
	config contract.Inbound
	listen string
}

func (s *discoveryAccepter) listenerBindings() []contract.RuntimeListener {
	return []contract.RuntimeListener{{Kind: "udp", Listen: s.listen}}
}

func (s *discoveryAccepter) ReconfigureContract(next contract.Inbound) (bool, error) {
	if next.Protocol.PeerDiscovery == nil {
		return false, nil
	}
	current := s.config
	discovery := *current.Protocol.PeerDiscovery
	discovery.BlockedPairIDs = next.Protocol.PeerDiscovery.BlockedPairIDs
	current.Protocol.PeerDiscovery = &discovery
	if !reflect.DeepEqual(current, next) {
		return false, nil
	}
	if err := next.Validate(); err != nil {
		return true, err
	}
	s.SetBlocked(discovery.BlockedPairIDs)
	s.config = next
	return true, nil
}

func (s *ContractStore) discoveryServer(id string) *discoveryAccepter {
	entry, _ := s.runtime.store.Load(id)
	server, _ := entry.server.(*discoveryAccepter)
	return server
}

func (s *ContractStore) PeerDiscoveryPairs(ctx context.Context, id string) (contract.PeerDiscoveryPairs, error) {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	config, err := s.store.Get(ctx, id)
	if err != nil {
		return contract.PeerDiscoveryPairs{}, err
	}
	discovery := config.Protocol.PeerDiscovery
	if discovery == nil {
		return contract.PeerDiscoveryPairs{}, errors.New("inbound is not a peer discovery server")
	}
	keys, err := discovery.Keys()
	if err != nil {
		return contract.PeerDiscoveryPairs{}, err
	}
	var registered map[string]peerrendezvous.PairStatus
	if server := s.discoveryServer(id); server != nil {
		registered = server.Pairs()
	}
	ids := make([]string, 0, len(keys)+len(registered))
	dynamic := make(map[string]bool, len(registered)+len(discovery.BlockedPairIDs))
	for id := range registered {
		dynamic[id] = true
	}
	for _, id := range discovery.BlockedPairIDs {
		dynamic[id] = true
	}
	for _, key := range keys {
		id := transport.PeerPairIDString(key)
		ids = append(ids, id)
		delete(dynamic, id)
	}
	ids = append(ids, slices.Sorted(maps.Keys(dynamic))...)
	items := make([]contract.PeerDiscoveryPair, 0, len(ids))
	for _, id := range ids {
		state := registered[id]
		item := contract.PeerDiscoveryPair{ID: id, Blocked: slices.Contains(discovery.BlockedPairIDs, id)}
		item.DialerEndpoint = endpointString(state.Dialer)
		item.PublisherEndpoint = endpointString(state.Publisher)
		if !state.KickUntil.IsZero() {
			item.RetryAt = state.KickUntil.UnixMilli()
		}
		items = append(items, item)
	}
	return contract.PeerDiscoveryPairs{Running: registered != nil, Items: items}, nil
}

func endpointString(addr netip.AddrPort) string {
	if addr.IsValid() {
		return addr.String()
	}
	return ""
}

func (s *ContractStore) UpdatePeerDiscoveryPair(ctx context.Context, request contract.PeerDiscoveryAction) error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	config, err := s.store.Get(ctx, request.ID)
	if err != nil {
		return err
	}
	discovery := config.Protocol.PeerDiscovery
	if discovery == nil {
		return errors.New("inbound is not a peer discovery server")
	}
	keys, err := discovery.Keys()
	if err != nil {
		return err
	}
	id, err := hex.DecodeString(request.PairID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != request.PairID {
		return errors.New("invalid peer discovery pairing ID")
	}
	server := s.discoveryServer(request.ID)
	isStatic := slices.ContainsFunc(keys, func(key [32]byte) bool { return transport.PeerPairID(key) == [16]byte(id) })
	registered := false
	if server != nil && !isStatic {
		_, registered = server.Pairs()[request.PairID]
	}
	if !isStatic && !registered && !slices.Contains(discovery.BlockedPairIDs, request.PairID) {
		return errors.New("peer discovery pairing does not exist")
	}
	switch request.Action {
	case "kick":
		if server == nil {
			return errors.New("peer discovery server is inactive")
		}
		return server.Kick([16]byte(id))
	case "block":
		if !slices.Contains(discovery.BlockedPairIDs, request.PairID) {
			discovery.BlockedPairIDs = append(discovery.BlockedPairIDs, request.PairID)
		}
	case "unblock":
		discovery.BlockedPairIDs = slices.DeleteFunc(discovery.BlockedPairIDs, func(id string) bool { return id == request.PairID })
	default:
		return errors.New("unknown peer discovery action")
	}
	if err := s.store.Save(secret.WithResolvedConfiguration(ctx), config, time.Now().Unix()); err != nil {
		return err
	}
	return s.runtime.SaveContract(config)
}

// Configuration editors may have been opened before an administrator blocked
// a pairing. Token edits preserve the current blocks for all retained tokens.
func preserveDiscoveryBlocks(next *contract.Inbound, previous contract.Inbound) {
	if next.Protocol.PeerDiscovery == nil || previous.Protocol.PeerDiscovery == nil {
		return
	}
	discovery := *next.Protocol.PeerDiscovery
	nextStatic, previousStatic := discoveryPairIDs(discovery.Tokens), discoveryPairIDs(previous.Protocol.PeerDiscovery.Tokens)
	discovery.BlockedPairIDs = nil
	for _, id := range previous.Protocol.PeerDiscovery.BlockedPairIDs {
		if nextStatic[id] || (!previousStatic[id] && len(discovery.RegistrationKeys) != 0) {
			discovery.BlockedPairIDs = append(discovery.BlockedPairIDs, id)
		}
	}
	next.Protocol.PeerDiscovery = &discovery
}

func discoveryPairIDs(tokens []string) map[string]bool {
	ids := make(map[string]bool, len(tokens))
	for _, token := range tokens {
		if key, err := transport.DecodePeerKey(token); err == nil {
			ids[transport.PeerPairIDString(key)] = true
		}
	}
	return ids
}
