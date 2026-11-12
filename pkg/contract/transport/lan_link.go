package transport

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const LANLinkType = "lan_link"

const lanLinkInvitationPrefix = "lan-link:v1:"

// LANLink configures an outbound from a publisher-issued invitation.
type LANLink struct {
	Invitation string `json:"invitation" secret:"true"`
	PrivateKey string `json:"privateKey,omitempty" secret:"true"`
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
	_, err := ParseLANLinkRoutes(i.Routes)
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
			p.Addr().IsMulticast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() || p.Addr().IsUnspecified() || (len(routes) != 0 && p.Addr().BitLen() != routes[0].Addr().BitLen()) {
			return nil, fmt.Errorf("invalid LAN Link route %q", value)
		}
		routes = append(routes, p)
	}
	return routes, nil
}
