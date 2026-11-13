package node

import (
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
)

type PeerTunnelPeer struct {
	NodeID   string   `json:"nodeId"`
	Name     string   `json:"name"`
	State    string   `json:"state"`
	Endpoint string   `json:"endpoint,omitempty"`
	TunnelIP string   `json:"tunnelIp"`
	Routes   []string `json:"routes"`
	// Link is the local side of the running LAN Link: this node's tunnel
	// address, UDP socket, pairing ID and the peer address in use.
	Link *transport.LANLinkStatus `json:"link,omitempty"`
}

type PeerTunnelPeers struct {
	Items []PeerTunnelPeer `json:"items"`
	Page  route.Page       `json:"page"`
}
