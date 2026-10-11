package ikev1

// Dead-peer detection (RFC 3706).
//
// IKEv1 has no liveness check of its own, so vendors settled on one built out of
// the pieces already there: an Informational exchange carrying a Notification
// payload of type R-U-THERE, answered with R-U-THERE-ACK echoing the sequence
// number. The SPI field carries the ISAKMP cookie pair, which is what says
// *which* SA is being asked about.
//
//	HDR*, HASH(1), N(R-U-THERE, seq)      -->
//	                                      <--  HDR*, HASH(1), N(R-U-THERE-ACK, seq)
//
// It exists here for two reasons. A gateway that has forgotten the SA — after a
// restart, or a client whose NAT binding moved — otherwise blackholes traffic
// indefinitely; and the outbound half is exactly what client.Prober needs, so
// dead-peer detection and the CLI's liveness probe are one mechanism rather
// than two.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// dpdSPILen is the Notification SPI for a DPD message: CKY-I | CKY-R.
const dpdSPILen = 16

// dpdDataLen is the four-octet sequence number that follows it.
const dpdDataLen = 4

// buildDPDNotify renders the Notification payload body for a DPD message.
func (s *Session) buildDPDNotify(msgType uint16, seq uint32) []byte {
	body := make([]byte, 8+dpdSPILen+dpdDataLen)
	binary.BigEndian.PutUint32(body[0:], doiIPsec)
	body[4] = protoISAKMP
	body[5] = dpdSPILen
	binary.BigEndian.PutUint16(body[6:], msgType)
	copy(body[8:16], s.initCookie[:])
	copy(body[16:24], s.respCookie[:])
	binary.BigEndian.PutUint32(body[24:], seq)
	return body
}

// parseDPDNotify reads a DPD Notification back, reporting false for a
// Notification that is not one.
func parseDPDNotify(body []byte) (msgType uint16, seq uint32, ok bool) {
	if len(body) < 8 {
		return 0, 0, false
	}
	spiSize := int(body[5])
	msgType = binary.BigEndian.Uint16(body[6:8])
	if msgType != notifyRUThere && msgType != notifyRUThereAck {
		return 0, 0, false
	}
	data := body[8:]
	if len(data) < spiSize+dpdDataLen {
		return 0, 0, false
	}
	return msgType, binary.BigEndian.Uint32(data[spiSize : spiSize+dpdDataLen]), true
}

// sendInformational sends one Informational exchange under a fresh message ID.
//
// Informational exchanges are unreliable by design (RFC 2408 section 4.8), so
// this deliberately bypasses the retransmit machinery: a lost DPD probe is
// answered by the next probe, not by resending this one, and arming the timer
// here would let a quiet moment tear down a healthy session.
func (s *Session) sendInformational(payloads []payload) error {
	if s.keys == nil {
		return errors.New("ikev1: no keys for an Informational exchange")
	}
	msgID := randSPI()
	_, chain := payloadChain(payloads)
	hash := s.keys.prf.Apply(s.keys.skeyidA, concat(be32(msgID), chain))

	firstType, body := payloadChain(append([]payload{{typ: payloadHash, body: hash}}, payloads...))
	ct, err := cbcEncrypt(s.keys.encKey, s.keys.quickModeIV(msgID), body)
	if err != nil {
		return err
	}
	return s.cfg.Send(assemble(s.mmHeader(exchangeInformational, flagEncryption, msgID), firstType, ct), s.floated)
}

// Ping sends a DPD R-U-THERE and returns a channel that closes when the peer
// acknowledges it. It is only meaningful on an established session; before then
// the exchange itself is the liveness evidence.
//
// The caller decides how long to wait. A closed channel means the peer answered;
// a caller that gives up simply stops listening, and the next Ping supersedes
// this one.
func (s *Session) Ping() (<-chan struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stDone {
		return nil, errors.New("ikev1: the session is not established")
	}
	s.dpdSeq++
	seq := s.dpdSeq
	ch := make(chan struct{})
	s.dpdWait = ch
	if err := s.sendInformational([]payload{
		{typ: payloadNotify, body: s.buildDPDNotify(notifyRUThere, seq)},
	}); err != nil {
		s.dpdWait = nil
		return nil, err
	}
	return ch, nil
}

// handleDPD answers an inbound R-U-THERE and completes a pending Ping on an
// R-U-THERE-ACK. It runs with the session lock held.
func (s *Session) handleDPD(h header, first uint8, rest []byte) error {
	// Informational exchanges carry their own IV chain, seeded from the message
	// ID like every other post-phase-1 exchange. It is not retained: each one is
	// a single message.
	iv := s.keys.quickModeIV(h.messageID)
	payloads, plain, consumed, err := s.recvDecrypt(&iv, first, rest)
	if err != nil {
		return err
	}
	hp, ok := findPayload(payloads, payloadHash)
	if !ok {
		return errors.New("informational exchange without HASH")
	}
	want := s.keys.prf.Apply(s.keys.skeyidA, concat(be32(h.messageID), afterHash(plain, payloads, consumed)))
	if !constEq(want, hp.body) {
		return errors.New("informational HASH verification failed")
	}
	np, ok := findPayload(payloads, payloadNotify)
	if !ok {
		return nil // a delete or some other notification-free message; nothing to do
	}
	msgType, seq, ok := parseDPDNotify(np.body)
	if !ok {
		return nil
	}
	switch msgType {
	case notifyRUThere:
		return s.sendInformational([]payload{
			{typ: payloadNotify, body: s.buildDPDNotify(notifyRUThereAck, seq)},
		})
	case notifyRUThereAck:
		if seq != s.dpdSeq {
			return fmt.Errorf("stale R-U-THERE-ACK (seq %d, awaiting %d)", seq, s.dpdSeq)
		}
		if s.dpdWait != nil {
			close(s.dpdWait)
			s.dpdWait = nil
		}
	}
	return nil
}
