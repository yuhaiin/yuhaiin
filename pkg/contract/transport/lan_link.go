package transport

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const LANLinkType = "lan_link"

const lanLinkInvitationPrefix = "lan-link:v1:"

// LANLink configures an outbound from a publisher-issued invitation.
type LANLink struct {
	Invitation string `json:"invitation" secret:"true"`
	PrivateKey string `json:"privateKey,omitempty" secret:"true"`
	// AllowIncoming delivers flows addressed to this client's tunnel address to
	// the same port on its loopback address. It takes effect only when the
	// gateway enables client-to-client traffic.
	AllowIncoming bool `json:"allowIncoming,omitempty"`
}

func (LANLink) ProtocolType() string { return LANLinkType }

func (c LANLink) Validate() error {
	if _, err := ParseLANLinkInvitation(c.Invitation); err != nil {
		return err
	}
	if c.PrivateKey != "" {
		if _, err := DecodePeerKey(c.PrivateKey); err != nil {
			return fmt.Errorf("LAN Link private key: %w", err)
		}
	}
	return nil
}

// LANLinkInvitation carries separate credentials for rendezvous and peer
// authentication. Only the publisher and the invited outbound know the token.
type LANLinkInvitation struct {
	Coordinator  string   `json:"coordinator"`
	Registration string   `json:"registration" secret:"true"`
	Token        string   `json:"token" secret:"true"`
	Routes       []string `json:"routes"`
	// Subnet is the tunnel network when the gateway relays client-to-client
	// traffic. The live assignment from the gateway takes precedence.
	Subnet string `json:"subnet,omitempty"`
	// Subnets lists every tunnel network of a dual-stack gateway, including
	// Subnet.
	Subnets []string `json:"subnets,omitempty"`
}

// Prefixes returns the routes and, when present, the tunnel subnets.
func (i LANLinkInvitation) Prefixes() ([]netip.Prefix, error) {
	routes, err := ParseLANLinkRoutes(i.Routes)
	if err != nil {
		return nil, err
	}
	subnets, err := ParseLANLinkSubnets(append([]string{i.Subnet}, i.Subnets...), routes)
	if err != nil {
		return nil, err
	}
	return append(routes, subnets...), nil
}

// ParseLANLinkSubnets parses tunnel subnets, at most one per IP family, that
// must not overlap routes. Empty and repeated values are skipped.
func ParseLANLinkSubnets(values []string, routes []netip.Prefix) ([]netip.Prefix, error) {
	var subnets []netip.Prefix
	for _, value := range values {
		if value == "" {
			continue
		}
		subnet, err := netip.ParsePrefix(value)
		if err != nil || subnet != subnet.Masked() || subnet.Bits() == 0 || subnet.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid LAN Link tunnel subnet %q", value)
		}
		if slices.Contains(subnets, subnet) {
			continue
		}
		if slices.ContainsFunc(subnets, func(p netip.Prefix) bool { return p.Addr().BitLen() == subnet.Addr().BitLen() }) {
			return nil, fmt.Errorf("LAN Link has two tunnel subnets in the family of %q", value)
		}
		for _, route := range routes {
			if route.Overlaps(subnet) {
				return nil, fmt.Errorf("LAN Link tunnel subnet %q overlaps route %s", value, route)
			}
		}
		subnets = append(subnets, subnet)
	}
	return subnets, nil
}

func (i LANLinkInvitation) Encode() (string, error) {
	if err := i.validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	return lanLinkInvitationPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func ParseLANLinkInvitation(value string) (LANLinkInvitation, error) {
	var invitation LANLinkInvitation
	payload, ok := strings.CutPrefix(strings.TrimSpace(value), lanLinkInvitationPrefix)
	if !ok || len(payload) > 16<<10 {
		return invitation, errors.New("invalid LAN Link invitation")
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(data, &invitation) != nil {
		return LANLinkInvitation{}, errors.New("invalid LAN Link invitation")
	}
	return invitation, invitation.validate()
}

func (i LANLinkInvitation) validate() error {
	if err := ValidatePeerCoordinator(i.Coordinator); err != nil {
		return err
	}
	if _, err := DecodePeerKey(i.Registration); err != nil {
		return errors.New("invalid LAN Link registration credential")
	}
	if _, err := DecodePeerKey(i.Token); err != nil {
		return errors.New("invalid LAN Link invitation token")
	}
	_, err := i.Prefixes()
	return err
}

func NewLANLinkToken() string {
	var key [32]byte
	rand.Read(key[:])
	return base64.StdEncoding.EncodeToString(key[:])
}

func NewLANLinkPrivateKey() (string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), nil
}

func ParseLANLinkRoutes(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 || len(values) > 128 {
		return nil, errors.New("LAN Link requires 1 to 128 LAN routes")
	}
	routes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		p, err := netip.ParsePrefix(value)
		if err != nil || p != p.Masked() || p.Bits() == 0 || p.Addr().Is4In6() ||
			p.Addr().IsMulticast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() || p.Addr().IsUnspecified() {
			return nil, fmt.Errorf("invalid LAN Link route %q", value)
		}
		routes = append(routes, p)
	}
	return routes, nil
}

// LAN Link path kinds: how the data plane reaches the peer.
const (
	LANLinkPathLAN    = "lan"
	LANLinkPathPublic = "public"
)

// LANLinkPathKind classifies a peer endpoint. onLink is set when the peer was
// verified on a directly attached network.
func LANLinkPathKind(addr netip.Addr, onLink bool) string {
	addr = addr.Unmap()
	if onLink || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return LANLinkPathLAN
	}
	return LANLinkPathPublic
}

// LANLinkStatus is the live state of one LAN Link pairing. It holds no secrets.
type LANLinkStatus struct {
	// PairingID identifies the pairing on the gateway.
	PairingID string `json:"pairingId"`
	// State is idle (not started yet), connecting or connected.
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	// Coordinator is the gateway address from the invitation.
	Coordinator string `json:"coordinator,omitempty"`
	// LocalIPs and PeerIPs are the tunnel addresses of this side and the
	// peer, IPv4 first.
	LocalIPs []string `json:"localIps,omitempty"`
	PeerIPs  []string `json:"peerIps,omitempty"`
	// Listen is the local UDP address carrying the tunnel.
	Listen string `json:"listen,omitempty"`
	// PeerEndpoint is the UDP address the tunnel currently sends to, and Path
	// says whether it is a LAN or a public address.
	PeerEndpoint string `json:"peerEndpoint,omitempty"`
	Path         string `json:"path,omitempty"`
	// Peers are the other clients of the gateway, reported when it enables
	// client-to-client traffic.
	Peers []LANLinkPeer `json:"peers,omitempty"`
}

// LANLinkPeer is another client of the same gateway as seen by a client.
type LANLinkPeer struct {
	Name string `json:"name,omitempty"`
	// Addresses are the peer's tunnel addresses, IPv4 first.
	Addresses []string `json:"addresses"`
	Online    bool     `json:"online"`
}
