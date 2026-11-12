package inbound

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
