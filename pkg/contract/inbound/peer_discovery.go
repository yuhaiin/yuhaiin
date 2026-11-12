package inbound

import (
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
)

type PeerDiscoveryPair struct {
	ID                string `json:"id"`
	Blocked           bool   `json:"blocked"`
	RetryAt           int64  `json:"retryAt,omitempty"`
	DialerEndpoint    string `json:"dialerEndpoint,omitempty"`
	PublisherEndpoint string `json:"publisherEndpoint,omitempty"`
}

type PeerDiscoveryPairs struct {
	Running bool                `json:"running"`
	Items   []PeerDiscoveryPair `json:"items"`
}

type PeerDiscoveryAction struct {
	ID     string `json:"id"`
	PairID string `json:"pairId"`
	Action string `json:"action"`
}

// Authorities returns publisher credentials authorized to enroll new invitations.
func (p PeerDiscoveryProtocol) Authorities() ([][32]byte, error) {
	if len(p.RegistrationKeys) > 64 {
		return nil, errors.New("too many peer discovery registration keys")
	}
	keys, err := p.Keys()
	if err != nil {
		return nil, err
	}
	seen := make(map[[32]byte]bool, len(keys)+len(p.RegistrationKeys))
	for _, key := range keys {
		seen[key] = true
	}
	authorities := make([][32]byte, 0, len(p.RegistrationKeys))
	for _, value := range p.RegistrationKeys {
		key, err := transport.DecodePeerKey(value)
		if err != nil || seen[key] {
			return nil, errors.New("invalid or duplicate peer discovery registration key")
		}
		seen[key] = true
		authorities = append(authorities, key)
	}
	return authorities, nil
}
