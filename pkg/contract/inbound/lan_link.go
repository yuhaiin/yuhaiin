package inbound

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	randv2 "math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
)

const ProtocolLANLink = transport.LANLinkType

const (
	maxLANLinkClients    = 1024
	maxLANLinkClientName = 64
	// DefaultLANLinkListen is the UDP address of the gateway's built-in
	// coordinator. All clients and their data share this one port.
	DefaultLANLinkListen = ":51821"
	DefaultLANLinkSTUN   = "stun.l.google.com:19302"
)

// LANLinkGateway is the complete configuration of a LAN Link gateway. The
// coordinator, credentials and client addressing are generated and owned by
// the gateway; only Networks is required from the user.
type LANLinkGateway struct {
	// Networks are the LAN networks shared with clients.
	Networks []string `json:"networks"`
	// Subnet is the generated tunnel network. It is stable once assigned.
	Subnet string `json:"subnet,omitempty"`
	// Listen is the UDP bind address of the built-in coordinator.
	Listen string `json:"listen,omitempty"`
	// PublicEndpoint is how clients reach Listen from outside (host:port). It is
	// detected with STUN when empty.
	PublicEndpoint string `json:"publicEndpoint,omitempty"`
	// STUNServer overrides the server used to detect the public endpoint.
	STUNServer string          `json:"stunServer,omitempty"`
	PrivateKey string          `json:"privateKey,omitempty" secret:"true"`
	Clients    []LANLinkClient `json:"clients,omitempty"`
}

// LANLinkClient holds the independent credentials of one invitation.
type LANLinkClient struct {
	ID string `json:"id"`
	// Name is a user label that tells clients apart.
	Name         string `json:"name,omitempty"`
	Slot         int    `json:"slot"`
	Token        string `json:"token" secret:"true"`
	Registration string `json:"registration" secret:"true"`
	Blocked      bool   `json:"blocked,omitempty"`
	CreatedAt    int64  `json:"createdAt,omitempty"`
}

func (LANLinkGateway) ProtocolType() string { return ProtocolLANLink }

func (p LANLinkGateway) ListenAddress() string {
	if p.Listen == "" {
		return DefaultLANLinkListen
	}
	return p.Listen
}

func (p LANLinkGateway) STUNAddress() string {
	if p.STUNServer == "" {
		return DefaultLANLinkSTUN
	}
	return p.STUNServer
}

// FillDefaults generates missing secrets and the tunnel subnet. An existing
// subnet is kept unless it overlaps the networks and no client uses it.
func (p *LANLinkGateway) FillDefaults() error {
	routes, err := transport.ParseLANLinkRoutes(p.Networks)
	if err != nil {
		return err
	}
	if pool, err := netip.ParsePrefix(p.Subnet); err == nil && len(p.Clients) == 0 &&
		(pool.Addr().BitLen() != routes[0].Addr().BitLen() || slices.ContainsFunc(routes, pool.Overlaps)) {
		p.Subnet = ""
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

func validateHostPort(value string, allowEmptyHost bool) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || (host == "" && !allowEmptyHost) {
		return fmt.Errorf("%q must be host:port", value)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return fmt.Errorf("invalid port in %q", value)
	}
	return nil
}

func (p LANLinkGateway) Validate() error {
	routes, err := transport.ParseLANLinkRoutes(p.Networks)
	if err != nil {
		return err
	}
	if err := validateHostPort(p.ListenAddress(), true); err != nil {
		return fmt.Errorf("LAN Link listen address: %w", err)
	}
	if p.PublicEndpoint != "" {
		if err := transport.ValidatePeerCoordinator(p.PublicEndpoint); err != nil {
			return fmt.Errorf("LAN Link public endpoint: %w", err)
		}
	}
	if err := validateHostPort(p.STUNAddress(), false); err != nil {
		return fmt.Errorf("LAN Link STUN server: %w", err)
	}
	if _, err := transport.DecodePeerKey(p.PrivateKey); err != nil {
		return fmt.Errorf("LAN Link private key: %w", err)
	}
	pool, err := netip.ParsePrefix(p.Subnet)
	if err != nil || pool != pool.Masked() || !pool.Addr().IsGlobalUnicast() || pool.Addr().Is4In6() ||
		pool.Addr().BitLen() != routes[0].Addr().BitLen() || pool.Bits() > pool.Addr().BitLen()-2 {
		return errors.New("LAN Link tunnel subnet must be a unicast network in the shared networks' address family with room for clients")
	}
	if slices.ContainsFunc(routes, pool.Overlaps) {
		return errors.New("LAN Link tunnel subnet overlaps a shared network")
	}
	if len(p.Clients) > maxLANLinkClients {
		return errors.New("too many LAN Link clients")
	}
	ids := make(map[string]bool, len(p.Clients))
	slots := make(map[int]bool, len(p.Clients))
	registrations := make(map[[32]byte]bool, len(p.Clients))
	for _, client := range p.Clients {
		if _, err := client.InvitationID(); err != nil {
			return err
		}
		if _, err := NormalizeLANLinkClientName(client.Name); err != nil {
			return err
		}
		if _, err := transport.DecodePeerKey(client.Token); err != nil {
			return fmt.Errorf("LAN Link client token: %w", err)
		}
		registration, err := transport.DecodePeerKey(client.Registration)
		if err != nil {
			return fmt.Errorf("LAN Link client registration: %w", err)
		}
		if ids[client.ID] || slots[client.Slot] || registrations[registration] {
			return errors.New("duplicate LAN Link client ID, address or credential")
		}
		if _, err := lanLinkAddress(pool, client.Slot); err != nil {
			return err
		}
		ids[client.ID], slots[client.Slot], registrations[registration] = true, true, true
	}
	return nil
}

// AddClient allocates an address and fresh, client-specific credentials.
func (p *LANLinkGateway) AddClient(now int64, name string) (LANLinkClient, error) {
	name, err := NormalizeLANLinkClientName(name)
	if err != nil {
		return LANLinkClient{}, err
	}
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
	client := LANLinkClient{
		ID: hex.EncodeToString(id[:]), Name: name, Slot: slot, Token: transport.NewLANLinkToken(),
		Registration: transport.NewLANLinkToken(), CreatedAt: now,
	}
	p.Clients = append(p.Clients, client)
	return client, nil
}

// NormalizeLANLinkClientName trims a client label and rejects one that is too
// long or holds control characters.
func NormalizeLANLinkClientName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxLANLinkClientName ||
		strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("LAN Link client name must be at most %d characters without control characters", maxLANLinkClientName)
	}
	return name, nil
}

func (c LANLinkClient) InvitationID() ([16]byte, error) {
	id, err := hex.DecodeString(c.ID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != c.ID {
		return [16]byte{}, errors.New("invalid LAN Link client ID")
	}
	return [16]byte(id), nil
}

// PairingID identifies the client's rendezvous pairing.
func (c LANLinkClient) PairingID() string {
	key, err := transport.DecodePeerKey(c.Registration)
	if err != nil {
		return ""
	}
	return transport.PeerPairIDString(key)
}

func (p LANLinkGateway) Addresses(slot int) (netip.Addr, netip.Addr, error) {
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

// randomLANLinkSubnet picks a private /22 (IPv4) or ULA /64 (IPv6) that does
// not overlap the shared networks.
func randomLANLinkSubnet(routes []netip.Prefix) (netip.Prefix, error) {
	if routes[0].Addr().Is4() {
		const (
			tenNets = 1 << 14 // 10.0.0.0/8 in /22 steps
			ranNets = 1 << 10 // 172.16.0.0/12
			homeNet = 1 << 6  // 192.168.0.0/16
			total   = tenNets + ranNets + homeNet
		)
		start := randv2.IntN(total)
		for i := range total {
			index := (start + i) % total
			var addr [4]byte
			switch {
			case index < tenNets:
				addr = [4]byte{10, byte(index >> 6), byte(index&63) << 2, 0}
			case index < tenNets+ranNets:
				n := index - tenNets
				addr = [4]byte{172, 16 + byte(n>>6), byte(n&63) << 2, 0}
			default:
				addr = [4]byte{192, 168, byte(index-tenNets-ranNets) << 2, 0}
			}
			pool := netip.PrefixFrom(netip.AddrFrom4(addr), 22)
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
	return netip.Prefix{}, errors.New("no private address range is free for the LAN Link tunnel; the shared networks cover every candidate")
}

// LANLinkInvitationRequest creates a client; Name is an optional label.
type LANLinkInvitationRequest struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type LANLinkInvitationResponse struct {
	Invitation string `json:"invitation" secret:"true"`
	ClientID   string `json:"clientId"`
	Name       string `json:"name,omitempty"`
	Address    string `json:"address"`
}

type LANLinkClientRequest struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
}

// LANLinkClientAction is one of kick, block, unblock or rename. Name is the
// new label for rename.
type LANLinkClientAction struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
	Action   string `json:"action"`
	Name     string `json:"name,omitempty"`
}

type LANLinkClientStatus struct {
	ID                string `json:"id"`
	Name              string `json:"name,omitempty"`
	Address           string `json:"address"`
	PairingID         string `json:"pairingId"`
	Online            bool   `json:"online"`
	Blocked           bool   `json:"blocked"`
	RetryAt           int64  `json:"retryAt,omitempty"`
	DialerEndpoint    string `json:"dialerEndpoint,omitempty"`
	PublisherEndpoint string `json:"publisherEndpoint,omitempty"`
	// PeerEndpoint is where the gateway sends this client's tunnel traffic,
	// and Path tells whether that is a LAN or a public address.
	PeerEndpoint string `json:"peerEndpoint,omitempty"`
	Path         string `json:"path,omitempty"`
	CreatedAt    int64  `json:"createdAt,omitempty"`
}

type LANLinkClients struct {
	Running        bool                  `json:"running"`
	Subnet         string                `json:"subnet,omitempty"`
	PublicEndpoint string                `json:"publicEndpoint,omitempty"`
	PublicError    string                `json:"publicError,omitempty"`
	Items          []LANLinkClientStatus `json:"items"`
}

type LANLinkNetwork struct {
	CIDR      string `json:"cidr"`
	Interface string `json:"interface"`
	Family    string `json:"family"`
}

// LANLinkNetworks lists shareable networks found on this host.
type LANLinkNetworks struct {
	Supported bool             `json:"supported"`
	Reason    string           `json:"reason,omitempty"`
	Items     []LANLinkNetwork `json:"items"`
}
