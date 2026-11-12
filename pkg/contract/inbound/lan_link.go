package inbound

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	randv2 "math/rand/v2"
	"net/netip"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
)

const ProtocolLANLink = transport.LANLinkType

const maxLANLinkClients = 1024

type LANLinkPublisher struct {
	Coordinator  string          `json:"coordinator"`
	Registration string          `json:"registration" secret:"true"`
	Subnet       string          `json:"subnet,omitempty"`
	Routes       []string        `json:"routes"`
	PrivateKey   string          `json:"privateKey,omitempty" secret:"true"`
	Clients      []LANLinkClient `json:"clients,omitempty"`
}

type LANLinkClient struct {
	ID    string `json:"id"`
	Slot  int    `json:"slot"`
	Token string `json:"token" secret:"true"`
}

func (LANLinkPublisher) ProtocolType() string { return ProtocolLANLink }

func (p *LANLinkPublisher) FillDefaults() error {
	routes, err := transport.ParseLANLinkRoutes(p.Routes)
	if err != nil {
		return err
	}
	if p.Subnet == "" {
		subnet, err := randomLANLinkSubnet(routes)
		if err != nil {
			return err
		}
		p.Subnet = subnet.String()
	}
	if p.PrivateKey == "" {
		p.PrivateKey, err = transport.NewLANLinkPrivateKey()
		if err != nil {
			return err
		}
	}
	return p.Validate()
}

func (p LANLinkPublisher) Validate() error {
	if err := transport.ValidatePeerCoordinator(p.Coordinator); err != nil {
		return err
	}
	if _, err := transport.DecodePeerKey(p.Registration); err != nil {
		return fmt.Errorf("LAN Link publisher registration: %w", err)
	}
	if _, err := transport.DecodePeerKey(p.PrivateKey); err != nil {
		return fmt.Errorf("LAN Link publisher private key: %w", err)
	}
	routes, err := transport.ParseLANLinkRoutes(p.Routes)
	if err != nil {
		return err
	}
	pool, err := netip.ParsePrefix(p.Subnet)
	if err != nil || pool != pool.Masked() || !pool.Addr().IsGlobalUnicast() || pool.Addr().Is4In6() ||
		pool.Addr().BitLen() != routes[0].Addr().BitLen() || pool.Bits() > pool.Addr().BitLen()-2 {
		return errors.New("LAN Link tunnel subnet must be a unicast network in the LAN routes' address family with room for clients")
	}
	if slices.ContainsFunc(routes, pool.Overlaps) {
		return errors.New("LAN Link tunnel subnet overlaps a LAN route")
	}
	if len(p.Clients) > maxLANLinkClients {
		return errors.New("too many LAN Link clients")
	}
	ids := make(map[string]bool, len(p.Clients))
	slots := make(map[int]bool, len(p.Clients))
	for _, client := range p.Clients {
		if _, err := client.InvitationID(); err != nil {
			return err
		}
		if _, err := transport.DecodePeerKey(client.Token); err != nil {
			return fmt.Errorf("LAN Link client token: %w", err)
		}
		if ids[client.ID] || slots[client.Slot] {
			return errors.New("duplicate LAN Link client ID or address")
		}
		if _, err := lanLinkAddress(pool, client.Slot); err != nil {
			return err
		}
		ids[client.ID], slots[client.Slot] = true, true
	}
	return nil
}

func (p *LANLinkPublisher) AddClient() (LANLinkClient, error) {
	pool, err := netip.ParsePrefix(p.Subnet)
	if err != nil {
		return LANLinkClient{}, err
	}
	used := make(map[int]bool, len(p.Clients))
	for _, client := range p.Clients {
		used[client.Slot] = true
	}
	slot := 1
	for used[slot] {
		slot++
	}
	if _, err := lanLinkAddress(pool, slot); err != nil {
		return LANLinkClient{}, err
	}
	var id [16]byte
	rand.Read(id[:])
	client := LANLinkClient{ID: hex.EncodeToString(id[:]), Slot: slot, Token: transport.NewLANLinkToken()}
	p.Clients = append(p.Clients, client)
	return client, nil
}

func (c LANLinkClient) InvitationID() ([16]byte, error) {
	id, err := hex.DecodeString(c.ID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != c.ID {
		return [16]byte{}, errors.New("invalid LAN Link client ID")
	}
	return [16]byte(id), nil
}

func (p LANLinkPublisher) Addresses(slot int) (netip.Addr, netip.Addr, error) {
	pool, err := netip.ParsePrefix(p.Subnet)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	client, err := lanLinkAddress(pool, slot)
	return pool.Addr().Next(), client, err
}

func lanLinkAddress(pool netip.Prefix, slot int) (netip.Addr, error) {
	if slot < 1 || slot > maxLANLinkClients {
		return netip.Addr{}, errors.New("LAN Link address pool is full")
	}
	base := pool.Addr()
	offset := slot + 1
	var addr netip.Addr
	if base.Is4() {
		bits := base.As4()
		value := binary.BigEndian.Uint32(bits[:]) + uint32(offset)
		binary.BigEndian.PutUint32(bits[:], value)
		addr = netip.AddrFrom4(bits)
	} else {
		bits := base.As16()
		value := binary.BigEndian.Uint64(bits[8:]) + uint64(offset)
		binary.BigEndian.PutUint64(bits[8:], value)
		addr = netip.AddrFrom16(bits)
	}
	if addr.Compare(base) <= 0 || !pool.Contains(addr) || (base.Is4() && !pool.Contains(addr.Next())) {
		return netip.Addr{}, errors.New("LAN Link address pool is full")
	}
	return addr, nil
}

func randomLANLinkSubnet(routes []netip.Prefix) (netip.Prefix, error) {
	if routes[0].Addr().Is4() {
		const privateNetworks = (1 << 16) + (1 << 12) + (1 << 8)
		start := randv2.IntN(privateNetworks)
		for i := range privateNetworks {
			index := (start + i) % privateNetworks
			var addr [4]byte
			switch {
			case index < 1<<16:
				addr = [4]byte{10, byte(index >> 8), byte(index), 0}
			case index < (1<<16)+(1<<12):
				addr = [4]byte{172, 16 + byte((index-(1<<16))>>8), byte(index), 0}
			default:
				addr = [4]byte{192, 168, byte(index), 0}
			}
			pool := netip.PrefixFrom(netip.AddrFrom4(addr), 24)
			if !slices.ContainsFunc(routes, pool.Overlaps) {
				return pool, nil
			}
		}
	} else {
		for range 64 {
			var addr [16]byte
			rand.Read(addr[1:8])
			addr[0] = 0xfd
			pool := netip.PrefixFrom(netip.AddrFrom16(addr), 64)
			if !slices.ContainsFunc(routes, pool.Overlaps) {
				return pool, nil
			}
		}
	}
	return netip.Prefix{}, errors.New("no available LAN Link subnet; specify a non-overlapping tunnel subnet")
}

type LANLinkInvitationResponse struct {
	Invitation string `json:"invitation" secret:"true"`
	ClientID   string `json:"clientId"`
	Address    string `json:"address"`
}

type LANLinkClientRequest struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
}
