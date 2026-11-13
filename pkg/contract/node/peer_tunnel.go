package node

import "github.com/Asutorufa/yuhaiin/pkg/contract/route"

type PeerTunnelPeer struct {
	NodeID   string   `json:"nodeId"`
	Name     string   `json:"name"`
	State    string   `json:"state"`
	Endpoint string   `json:"endpoint,omitempty"`
	Routes   []string `json:"routes"`
}

type PeerTunnelPeers struct {
	Items []PeerTunnelPeer `json:"items"`
	Page  route.Page       `json:"page"`
}
