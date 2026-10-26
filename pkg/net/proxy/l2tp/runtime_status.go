package l2tp

import (
	"errors"
	"net"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/l2tp/native"
)

var _ contract.NodeRuntimeStatusProvider = (*Client)(nil)
var _ contract.NodeRuntimeStatusProvider = (*reconnectingClient)(nil)

// NodeRuntimeStatus reads the existing native session without constructing,
// authenticating or probing a new tunnel. Error details are deliberately bounded.
func (c *Client) NodeRuntimeStatus() contract.ProtocolRuntimeStatus {
	s := contract.ProtocolRuntimeStatus{State: "unknown", UpdatedAt: time.Now().Unix()}
	if c.session == nil {
		return s
	}
	switch err := c.session.Err(); {
	case err == nil:
		s.State = "connected"
	case errors.Is(err, native.ErrAuth):
		s.State = "authentication_failed"
	case errors.Is(err, net.ErrClosed):
		s.State = "closed"
	default:
		s.State = "failed"
		s.LastError = "native tunnel session failed"
	}
	if s.State == "connected" && c.cfg.Static {
		s.State = "configured"
	}
	return s
}

func (r *reconnectingClient) NodeRuntimeStatus() contract.ProtocolRuntimeStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.stopped {
		return contract.ProtocolRuntimeStatus{State: "closed", UpdatedAt: time.Now().Unix()}
	}
	if r.current != nil {
		return r.current.NodeRuntimeStatus()
	}
	state := "reconnecting"
	if r.failure != nil {
		state = "authentication_failed"
	}
	return contract.ProtocolRuntimeStatus{State: state, UpdatedAt: time.Now().Unix()}
}
