// IKE_INTERMEDIATE (RFC 9242) carrying an additional key exchange (RFC 9370),
// which is how a post-quantum KEM is bolted onto IKEv2 without changing
// IKE_SA_INIT: the classical group still runs in IKE_SA_INIT, and ML-KEM runs
// in a protected exchange afterwards, so the KEM's large public key and
// ciphertext never appear in an unauthenticated, amplifiable datagram.
//
//	initiator                                   responder
//	  |-- IKE_SA_INIT (SA{.. ADDKE1=ML-KEM-768}, KE, Ni, N(INTERMEDIATE_SUP)) -->|
//	  |<-- IKE_SA_INIT (SA{.. ADDKE1=ML-KEM-768}, KE, Nr, N(INTERMEDIATE_SUP)) --|
//	  |                    SKEYSEED from the classical DH                        |
//	  |-- IKE_INTERMEDIATE SK{KEi = ML-KEM encapsulation key} ------------------->|
//	  |<-- IKE_INTERMEDIATE SK{KEr = ML-KEM ciphertext} -------------------------|
//	  |          SKEYSEED = prf(SK_d, SK(1) | Ni | Nr); keys re-expanded         |
//	  |-- IKE_AUTH SK{IDi, AUTH(.. | IntAuth), SA, TSi, TSr} ------------------->|
//
// The KEM is asymmetric where Diffie-Hellman is not: the *initiator* sends its
// encapsulation (public) key and the *responder* encapsulates to it, returning
// only a ciphertext. The responder therefore holds no private key and keeps no
// state between the two messages — it derives the shared secret at the moment
// it encapsulates.
package ike

import (
	"crypto/mlkem"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// intAuthBlob returns IntAuth_[i/r]*A | IntAuth_[i/r]*P for one IKE_INTERMEDIATE
// message (RFC 9242 section 3.3):
//
//   - A is the IKE header through the end of the Encrypted payload's generic
//     header;
//   - P is the inner payloads in plaintext, before encryption.
//
// Both length fields are rewritten to count only what is covered, i.e. as if the
// IV, Padding, Pad Length and ICV were absent. That adjustment is the whole
// subtlety here: it makes the blob independent of the cipher, so an endpoint
// computes the same value whether it is about to encrypt the message or has
// just decrypted one.
func intAuthBlob(hdr payload.Header, firstInner payload.PayloadType, inner []byte) []byte {
	skPayloadLen := 4 + len(inner)
	hdr.NextPayload = payload.TypeSK
	hdr.Version = 0x20
	hdr.Length = uint32(payload.HeaderLen + skPayloadLen)

	out := make([]byte, 0, payload.HeaderLen+4+len(inner))
	out = hdr.Marshal(out)
	out = append(out, byte(firstInner), 0x00, byte(skPayloadLen>>8), byte(skPayloadLen))
	return append(out, inner...)
}

// chainIntAuth folds one message into a running IntAuth chain (RFC 9242
// section 3.3):
//
//	IntAuth_x1 = prf(SK_px1, blob1)
//	IntAuth_xN = prf(SK_pxN, IntAuth_xN-1 | blobN)
//
// skp is the SK_p for this direction as it stood *before* this exchange — the
// keys are re-derived afterwards, and using the new ones would put the two
// endpoints one round out of step with each other.
func chainIntAuth(prf *cryptoutil.PRF, skp, prev, blob []byte) []byte {
	if len(prev) == 0 {
		return prf.Apply(skp, blob)
	}
	seed := make([]byte, 0, len(prev)+len(blob))
	seed = append(seed, prev...)
	seed = append(seed, blob...)
	return prf.Apply(skp, seed)
}

// finalIntAuth assembles the value appended to both endpoints' signed octets
// (RFC 9242 section 3.3):
//
//	IntAuth = IntAuth_iN | IntAuth_rN | IKE_AUTH_MID
//
// Note both endpoints append the *same* IntAuth: each chain covers one
// direction, but every endpoint sees both directions and so computes both.
// Returns nil when no IKE_INTERMEDIATE exchange took place, which makes the
// AUTH computation degrade exactly to plain RFC 7296.
func finalIntAuth(intAuthI, intAuthR []byte, ikeAuthMsgID uint32) []byte {
	if len(intAuthI) == 0 && len(intAuthR) == 0 {
		return nil
	}
	out := make([]byte, 0, len(intAuthI)+len(intAuthR)+4)
	out = append(out, intAuthI...)
	out = append(out, intAuthR...)
	return binary.BigEndian.AppendUint32(out, ikeAuthMsgID)
}

// intAuth returns the IntAuth value for this SA's AUTH computation, given the
// message ID of the first IKE_AUTH request. Nil when no IKE_INTERMEDIATE
// exchange ran, which is the overwhelmingly common case.
func (sa *IKESA) intAuth(ikeAuthMsgID uint32) []byte {
	return finalIntAuth(sa.IntAuthI, sa.IntAuthR, ikeAuthMsgID)
}

// intAuth is the client's equivalent of [IKESA.intAuth].
func (c *Client) intAuth(ikeAuthMsgID uint32) []byte {
	return finalIntAuth(c.intAuthI, c.intAuthR, ikeAuthMsgID)
}

// addIntermediateNotify appends INTERMEDIATE_EXCHANGE_SUPPORTED to an
// IKE_SA_INIT payload chain (RFC 9242 section 3.1).
func addIntermediateNotify(b *payload.Builder) {
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.IntermediateExchangeSupported,
	}))
}

// hasIntermediateSupport reports whether a peer's IKE_SA_INIT advertised
// INTERMEDIATE_EXCHANGE_SUPPORTED.
func hasIntermediateSupport(msg *payload.Message) bool {
	for _, p := range msg.Payloads {
		if p.Type != payload.TypeNotify {
			continue
		}
		if n, err := payload.ParseNotify(p.Body); err == nil && n.Type == payload.IntermediateExchangeSupported {
			return true
		}
	}
	return false
}

// kemEncapsulate performs the responder's half of a KEM exchange: given the
// initiator's encapsulation key, return the ciphertext to send back and the
// shared secret to mix into SKEYSEED. Both are needed — discarding the secret
// leaves the responder keyed off the old SKEYSEED while the initiator moves to
// the new one, and every subsequent message fails to decrypt.
func kemEncapsulate(group uint16, peerPublic []byte) (ciphertext, shared []byte, err error) {
	if group != payload.MLKEM768 {
		return nil, nil, fmt.Errorf("ike: unsupported additional key exchange method %d", group)
	}
	ek, err := mlkem.NewEncapsulationKey768(peerPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("ike: ml-kem-768 encapsulation key: %w", err)
	}
	shared, ciphertext = ek.Encapsulate()
	return ciphertext, shared, nil
}

// rekeyFromAdditionalExchange applies RFC 9370 section 2.2.2 after an additional
// key exchange has produced a shared secret:
//
//	SKEYSEED(n) = prf(SK_d(n-1), SK(n) | Ni | Nr)
//	{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}(n)
//	    = prf+(SKEYSEED(n), Ni | Nr | SPIi | SPIr)
//
// The nonces are the original IKE_SA_INIT nonces, not per-exchange ones.
func rekeyFromAdditionalExchange(suite Suite, keys SAKeys, shared, ni, nr []byte, spiI, spiR uint64) SAKeys {
	skeyseed := DeriveIntermediateSKEYSEED(suite.PRF, keys.SKd, shared, ni, nr)
	return expandIKEKeys(suite.PRF, skeyseed, ni, nr, spiI, spiR,
		suite.encKeyLen(), suite.integKeyLen())
}

// handleIKEIntermediate answers an IKE_INTERMEDIATE request. The caller
// (handleSecured) already holds sa.mu.
func (s *Server) handleIKEIntermediate(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	if sa.State != StateSAInitDone && sa.State != StateIntermediate {
		s.log.Printf("ikev2: IKE_INTERMEDIATE from %s in wrong state %s", remote, sa.State)
		return
	}
	if sa.ADDKEGroup == 0 {
		// Nothing was negotiated, so there is nothing this exchange could carry.
		// Refusing is better than answering an empty message: it surfaces a peer
		// that skipped negotiation instead of letting the handshake drift on.
		s.log.Printf("ikev2: IKE_INTERMEDIATE from %s but no additional key exchange was negotiated", remote)
		s.respondEncryptedNotify(sa, payload.IKE_INTERMEDIATE, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}

	var ke payload.KEPayload
	found := false
	for _, in := range inners {
		if in.Type != payload.TypeKE {
			continue
		}
		parsed, err := payload.ParseKE(in.Body)
		if err != nil {
			s.log.Printf("ikev2: IKE_INTERMEDIATE KE parse from %s: %v", remote, err)
			return
		}
		ke, found = parsed, true
		break
	}
	if !found {
		s.log.Printf("ikev2: IKE_INTERMEDIATE from %s carried no KE payload", remote)
		s.respondEncryptedNotify(sa, payload.IKE_INTERMEDIATE, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}
	if ke.Group != sa.ADDKEGroup {
		// RFC 9370 section 2.1: the KE payload's method must match the n-th
		// negotiated additional key exchange.
		s.log.Printf("ikev2: IKE_INTERMEDIATE from %s used method %d, negotiated %d", remote, ke.Group, sa.ADDKEGroup)
		s.respondEncryptedNotify(sa, payload.IKE_INTERMEDIATE, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}

	ct, shared, err := kemEncapsulate(ke.Group, ke.KeyData)
	if err != nil {
		s.log.Printf("ikev2: IKE_INTERMEDIATE from %s: %v", remote, err)
		s.respondEncryptedNotify(sa, payload.IKE_INTERMEDIATE, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}

	// Fold the request into the initiator's IntAuth chain before re-keying: the
	// chain is keyed by the SK_p in force for this exchange (RFC 9242 3.3).
	reqInner, err := reencodeInners(inners)
	if err != nil {
		s.log.Printf("ikev2: IKE_INTERMEDIATE from %s: %v", remote, err)
		return
	}
	reqHdr := hdr
	reqHdr.Flags = payload.FlagInitiator
	sa.IntAuthI = chainIntAuth(sa.Suite.PRF, sa.Keys.SKpi, sa.IntAuthI,
		intAuthBlob(reqHdr, inners[0].Type, reqInner))

	b := payload.NewBuilder()
	b.Add(payload.TypeKE, false, payload.MarshalKE(payload.KEPayload{Group: ke.Group, KeyData: ct}))
	respInner := b.Bytes()
	respHdr := payload.Header{
		InitiatorSPI: sa.InitiatorSPI, ResponderSPI: sa.ResponderSPI, Version: 0x20,
		ExchangeType: payload.IKE_INTERMEDIATE,
		Flags:        payload.FlagResponse, MessageID: hdr.MessageID,
	}
	sa.IntAuthR = chainIntAuth(sa.Suite.PRF, sa.Keys.SKpr, sa.IntAuthR,
		intAuthBlob(respHdr, b.FirstType(), respInner))

	// Send under the *old* keys — the peer has not re-keyed either until it has
	// this message — then re-key.
	s.respondEncrypted(sa, payload.IKE_INTERMEDIATE, hdr.MessageID, b.FirstType(), respInner, remote)

	sa.Keys = rekeyFromAdditionalExchange(sa.Suite, sa.Keys, shared, sa.Ni, sa.Nr, sa.InitiatorSPI, sa.ResponderSPI)
	sa.State = StateIntermediate
	sa.RecvMsgID++
}

// reencodeInners rebuilds the plaintext inner payload chain from parsed
// payloads, so IntAuth_*P can be computed on the receive side. The bytes must
// match what the peer encrypted exactly, including the NextPayload links.
func reencodeInners(inners []payload.RawPayload) ([]byte, error) {
	if len(inners) == 0 {
		return nil, fmt.Errorf("ike: no inner payloads to re-encode")
	}
	out := make([]byte, 0, 64)
	for i, in := range inners {
		next := payload.NoNextPayload
		if i+1 < len(inners) {
			next = inners[i+1].Type
		}
		var crit byte
		if in.Critical {
			crit = 0x80
		}
		total := 4 + len(in.Body)
		out = append(out, byte(next), crit, byte(total>>8), byte(total))
		out = append(out, in.Body...)
	}
	return out, nil
}

// sendIntermediateExchange runs the initiator's side: generate an ML-KEM-768
// keypair, send the encapsulation key, decapsulate the responder's ciphertext,
// and re-key from the resulting shared secret.
func (c *Client) sendIntermediateExchange() error {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return fmt.Errorf("ike: ml-kem-768 keygen: %w", err)
	}

	b := payload.NewBuilder()
	b.Add(payload.TypeKE, false, payload.MarshalKE(payload.KEPayload{
		Group: c.addkeGroup, KeyData: dk.EncapsulationKey().Bytes(),
	}))
	reqInner := b.Bytes()

	msgID := c.sendMsgID
	c.sendMsgID++
	hdr := payload.Header{
		InitiatorSPI: c.spiI, ResponderSPI: c.spiR, Version: 0x20,
		ExchangeType: payload.IKE_INTERMEDIATE, Flags: payload.FlagInitiator, MessageID: msgID,
	}
	pkt, err := buildEncryptedMessage(hdr, c.suite, c.keys, dirInitiatorToResponder, b.FirstType(), reqInner)
	if err != nil {
		return fmt.Errorf("ike: build IKE_INTERMEDIATE: %w", err)
	}
	c.intAuthI = chainIntAuth(c.suite.PRF, c.keys.SKpi, c.intAuthI,
		intAuthBlob(hdr, b.FirstType(), reqInner))

	if err := c.writeIKE(pkt); err != nil {
		return err
	}

	raw, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("ike: IKE_INTERMEDIATE read: %w", err)
	}
	respHdr, err := payload.ParseHeader(raw)
	if err != nil {
		return err
	}
	if respHdr.MessageID != msgID {
		return fmt.Errorf("ike: IKE_INTERMEDIATE msgID mismatch: got %d, want %d", respHdr.MessageID, msgID)
	}
	if respHdr.ExchangeType != payload.IKE_INTERMEDIATE {
		return fmt.Errorf("ike: IKE_INTERMEDIATE answered with %s", respHdr.ExchangeType)
	}

	inners, err := decryptAndParseInners(raw, respHdr, c.suite, c.keys, dirResponderToInitiator)
	if err != nil {
		return fmt.Errorf("ike: IKE_INTERMEDIATE decrypt: %w", err)
	}
	if n := findInnerNotifyError(inners); n != 0 {
		return fmt.Errorf("ike: IKE_INTERMEDIATE rejected: notify %d", n)
	}

	respInner, err := reencodeInners(inners)
	if err != nil {
		return err
	}
	c.intAuthR = chainIntAuth(c.suite.PRF, c.keys.SKpr, c.intAuthR,
		intAuthBlob(respHdr, inners[0].Type, respInner))

	for _, in := range inners {
		if in.Type != payload.TypeKE {
			continue
		}
		ke, perr := payload.ParseKE(in.Body)
		if perr != nil {
			return fmt.Errorf("ike: IKE_INTERMEDIATE KE parse: %w", perr)
		}
		if ke.Group != c.addkeGroup {
			return fmt.Errorf("ike: IKE_INTERMEDIATE used method %d, negotiated %d", ke.Group, c.addkeGroup)
		}
		shared, derr := dk.Decapsulate(ke.KeyData)
		if derr != nil {
			return fmt.Errorf("ike: ml-kem-768 decapsulate: %w", derr)
		}
		c.keys = rekeyFromAdditionalExchange(c.suite, c.keys, shared, c.ni, c.nr, c.spiI, c.spiR)
		return nil
	}
	return fmt.Errorf("ike: IKE_INTERMEDIATE response carried no KE payload")
}

// decryptAndParseInners decrypts a received SK-protected message and returns its
// inner payloads.
func decryptAndParseInners(raw []byte, hdr payload.Header, suite Suite, keys SAKeys, dir keyDir) ([]payload.RawPayload, error) {
	msg, err := payload.ParseMessage(raw)
	if err != nil {
		return nil, err
	}
	skPay := msg.Find(payload.TypeSK)
	if skPay == nil {
		return nil, fmt.Errorf("ike: missing SK payload")
	}
	firstInner, inner, err := decryptSK(raw, hdr, *skPay, suite, keys, dir)
	if err != nil {
		return nil, err
	}
	return parseInnerPayloads(firstInner, inner)
}
