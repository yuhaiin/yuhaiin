package ike

import (
	"context"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// Client liveness (RFC 7296 dead-peer detection). After the handshake the data
// path owns the socket's reads, so the client can no longer read IKE responses
// inline. Attach switches the client into a mode where the data path delivers
// received IKE datagrams via Deliver and the control exchanges below read them
// from an inbox channel. A dead peer is detected by SendDPD: an empty
// INFORMATIONAL request that a live responder must answer (RFC 7296 section
// 2.4). Higher layers turn a run of unanswered probes into a torn-down tunnel.

// Attach puts the client into post-handshake control mode: control exchanges
// (DPD, rekey) now read the datagrams the data path feeds in through Deliver
// rather than reading the socket, which the data path now owns. It is called
// once, after Connect, before the caller starts pumping the data path.
func (c *Client) Attach() {
	c.inbox = make(chan []byte, 32)
	c.attached.Store(true)
}

// Deliver hands one received IKE datagram (the message bytes, the non-ESP
// marker already stripped) to whichever control exchange is awaiting a
// response. It never blocks: if no exchange is waiting the datagram is dropped,
// which is correct — an unmatched IKE message post-handshake is a retransmit or
// an unsolicited notify we do not act on. Safe to call from the data-path read
// loop.
func (c *Client) Deliver(pkt []byte) {
	if !c.attached.Load() {
		return
	}
	select {
	case c.inbox <- pkt:
	default:
	}
}

// recvControl reads one delivered datagram, honouring ctx's deadline. It is the
// attached-mode counterpart of readMessage.
func (c *Client) recvControl(ctx context.Context) func() ([]byte, error) {
	return func() ([]byte, error) {
		select {
		case pkt := <-c.inbox:
			return pkt, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// SendDPD runs one dead-peer-detection exchange: an empty INFORMATIONAL request
// the responder must answer with an (empty) INFORMATIONAL response. It returns
// nil only if a well-formed response arrived before ctx expired. The exchange
// is serialized with roam and rekey via exchMu so message IDs never interleave.
//
// It requires Attach to have been called; before that the data path is not yet
// reading the socket and a caller should use the handshake path instead.
func (c *Client) SendDPD(ctx context.Context) error {
	c.exchMu.Lock()
	defer c.exchMu.Unlock()

	if !c.attached.Load() {
		return errNotAttached
	}

	msgID := c.sendMsgID
	pkts, err := c.seal(payload.INFORMATIONAL, msgID, payload.NoNextPayload, nil)
	if err != nil {
		return err
	}
	if err := c.writeIKEAll(pkts); err != nil {
		return err
	}
	// The response is an empty (but encrypted) INFORMATIONAL: recvInnersFrom
	// decrypts and returns an empty payload list, or surfaces an error notify.
	if _, err := c.recvInnersFrom(c.recvControl(ctx)); err != nil {
		return err
	}
	c.sendMsgID = msgID + 1
	return nil
}
