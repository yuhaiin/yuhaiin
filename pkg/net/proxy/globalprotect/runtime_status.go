package globalprotect

import (
	"errors"
	"net"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

var _ contract.NodeRuntimeStatusProvider = (*Client)(nil)
var _ contract.NodeRuntimeStatusProvider = (*reconnectingClient)(nil)

// NodeRuntimeStatus reads the existing native session without constructing,
// authenticating or probing a new tunnel. Error details are deliberately bounded.
func (c *Client) NodeRuntimeStatus() contract.ProtocolRuntimeStatus {
	s := contract.ProtocolRuntimeStatus{State: "unknown", UpdatedAt: time.Now().Unix()}
	if c.done == nil {
		return s
	}
	switch err := c.stateError(); {
	case err == nil:
		s.State = "connected"
	case errors.Is(err, errAuthenticationRejected) || errors.Is(err, ErrInteractiveAuth):
		s.State = "authentication_failed"
	case errors.Is(err, errGatewayIdleDisconnect):
		s.State = "idle"
	case errors.Is(err, net.ErrClosed):
		s.State = "closed"
	default:
		s.State = "failed"
		s.LastError = "native tunnel session failed"
	}
	return s
}
func (c *reconnectingClient) NodeRuntimeStatus() contract.ProtocolRuntimeStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := contract.ProtocolRuntimeStatus{State: "reconnecting", UpdatedAt: time.Now().Unix()}
	switch {
	case c.closed:
		s.State = "closed"
	case c.failure != nil:
		s.State = "authentication_failed"
	case c.client != nil:
		return c.client.NodeRuntimeStatus()
	case c.waitingForDemand:
		s.State = "idle"
	}
	return s
}
