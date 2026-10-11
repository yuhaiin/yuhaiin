package l2tpv3

import (
	"fmt"
	"net"
)

// SessionConfig is one L2TPv3 Ethernet pseudowire.
//
// The two cookies are the part that gets implemented backwards. RFC 3931
// section 4.1.2.1 makes the cookie a property of the RECEIVER: each end picks
// the value it wants to see on packets arriving for its own session and tells
// the peer, so the two directions carry different cookies and either may carry
// none. Hence the field names here describe whose receive side a cookie belongs
// to, not which way the packet is travelling:
//
//	LocalCookie  -- what WE chose; verified on every packet we receive
//	RemoteCookie -- what the PEER chose; written into every packet we send
//
// Swap them and a veepin-to-veepin tunnel still works perfectly, because both
// ends are wrong in the same direction. Only a real peer notices. That is the
// failure mode TestCookieIsChosenByTheReceiver exists to prevent.
type SessionConfig struct {
	// LocalSessionID is the Session ID the peer puts on packets it sends us,
	// and the key we demux inbound packets by.
	LocalSessionID uint32
	// RemoteSessionID is the Session ID we put on packets we send.
	RemoteSessionID uint32

	LocalCookie  []byte // 0, 4 or 8 octets, chosen by us
	RemoteCookie []byte // 0, 4 or 8 octets, chosen by the peer

	// Sublayer records whether the session carries the Default L2-Specific
	// Sublayer. It is agreed out of band for a static pseudowire and negotiated
	// for a dynamic one -- never inferred from a packet, because Linux sends an
	// all-zeros sublayer that is indistinguishable from absence by inspection.
	Sublayer bool

	// PeerAddr is where to send. A client knows it from the start; a server
	// leaves it nil and learns it from the first packet that passes the cookie
	// check.
	PeerAddr *net.UDPAddr
}

// Validate rejects a configuration the wire format cannot express.
func (c *SessionConfig) Validate() error {
	if c.LocalSessionID == 0 {
		return fmt.Errorf("l2tpv3: local session ID must be non-zero")
	}
	if c.RemoteSessionID == 0 {
		return fmt.Errorf("l2tpv3: remote session ID must be non-zero")
	}
	if !ValidCookieLen(len(c.LocalCookie)) {
		return fmt.Errorf("l2tpv3: local cookie is %d octets: %w", len(c.LocalCookie), ErrCookieLen)
	}
	if !ValidCookieLen(len(c.RemoteCookie)) {
		return fmt.Errorf("l2tpv3: peer cookie is %d octets: %w", len(c.RemoteCookie), ErrCookieLen)
	}
	return nil
}

// Overhead is the number of octets this session adds to each Ethernet frame on
// the wire, before the outer IP and UDP headers.
func (c *SessionConfig) Overhead() int {
	return DataHeaderLen(len(c.RemoteCookie), c.Sublayer)
}
