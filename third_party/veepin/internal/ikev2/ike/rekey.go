package ike

import (
	"context"
	"fmt"
	"net"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// Child SA rekey (RFC 7296 section 2.8). An ESP SA has a finite lifetime — a
// byte ceiling and a wall-clock soft lifetime — after which its keys must be
// replaced or the tunnel stops. Rekeying does this without dropping traffic: the
// initiator runs a CREATE_CHILD_SA exchange to negotiate a fresh SA (new SPIs,
// new keys derived from fresh nonces), the data path is swapped onto it, and the
// old SA is deleted. It reuses the post-handshake control channel (Attach) and
// serializes with DPD and MOBIKE roam via exchMu.
//
// The initiator side lives here; the responder's CREATE_CHILD_SA and Delete
// handling is in child_info.go.

// RekeyChild negotiates a replacement Child SA and returns the new parameters as
// a ClientResult (so the caller can BuildTunnel it) together with the inbound
// SPI of the SA being replaced, which the caller retires once the swap is live.
// It updates the client's own notion of the current Child SA on success.
//
// It requires Attach (post-handshake control mode); the exchange reads its
// response from the delivered inbox, not the socket.
func (c *Client) RekeyChild(ctx context.Context) (newRes *ClientResult, oldInSPI uint32, err error) {
	c.exchMu.Lock()
	defer c.exchMu.Unlock()

	if !c.attached.Load() {
		return nil, 0, errNotAttached
	}
	if c.result == nil {
		return nil, 0, fmt.Errorf("ike: no Child SA to rekey")
	}
	oldInSPI = c.result.InboundSPI
	oldOutSPI := c.result.OutboundSPI

	newInSPI := newChildSPI()
	ni := mustNonce(32)
	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTrafficV4()}}

	b := payload.NewBuilder()
	// REKEY_SA identifies the SA being replaced (RFC 7296 2.8): its SPI is the one
	// the peer sends to — i.e. our old outbound SPI (the peer's inbound). This is
	// what lets a compliant responder (strongSwan) delete the old SA rather than
	// treat this as an unrelated new child.
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoESP, Type: payload.RekeySA, SPI: u32BE(oldOutSPI),
	}))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
		Proposals: DefaultESPProposals(u32BE(newInSPI)),
	}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(ni))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))

	msgID := c.sendMsgID
	pkts, err := c.seal(payload.CREATE_CHILD_SA, msgID, b.FirstType(), b.Bytes())
	if err != nil {
		return nil, 0, err
	}
	if err := c.writeIKEAll(pkts); err != nil {
		return nil, 0, fmt.Errorf("ike: rekey send: %w", err)
	}
	inners, err := c.recvInnersFrom(c.recvControl(ctx))
	if err != nil {
		return nil, 0, fmt.Errorf("ike: rekey response: %w", err)
	}

	saPay := findInner(inners, payload.TypeSA)
	noncePay := findInner(inners, payload.TypeNonce)
	if saPay == nil || noncePay == nil {
		return nil, 0, fmt.Errorf("ike: rekey response missing SA/Nonce")
	}
	espSA, err := payload.ParseSA(saPay.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("ike: rekey response SA: %w", err)
	}
	es, _, err := SelectESPSuite(espSA)
	if err != nil {
		return nil, 0, fmt.Errorf("ike: rekey response suite: %w", err)
	}
	nr := payload.ParseNonce(noncePay.Body)

	var newOutSPI uint32
	if len(espSA.Proposals) > 0 && len(espSA.Proposals[0].SPI) == 4 {
		newOutSPI = beU32(espSA.Proposals[0].SPI)
	}
	if newOutSPI == 0 {
		return nil, 0, fmt.Errorf("ike: rekey response carried no SPI")
	}

	// Derive the new Child keys exactly as the initial handshake does: KEYMAT
	// from SK_d over Ni|Nr of *this* exchange, split enc_i|integ_i|enc_r|integ_r.
	encLen := es.Cipher.KeyLen()
	integLen := 0
	if es.Integ != nil {
		integLen = es.Integ.KeyLen
	}
	km := DeriveChildKeys(c.suite.PRF, c.keys.SKd, nil, ni, nr, 2*encLen+2*integLen)
	off := 0
	take := func(n int) []byte { v := km[off : off+n]; off += n; return v }

	// Copy the stable fields (assigned address, server endpoint, suite) and
	// replace the SPIs and keys.
	res := *c.result
	res.InboundSPI = newInSPI
	res.OutboundSPI = newOutSPI
	res.Suite = es
	res.EncKeyOut = take(encLen)
	if integLen > 0 {
		res.IntegKeyOut = take(integLen)
	} else {
		res.IntegKeyOut = nil
	}
	res.EncKeyIn = take(encLen)
	if integLen > 0 {
		res.IntegKeyIn = take(integLen)
	} else {
		res.IntegKeyIn = nil
	}

	c.sendMsgID = msgID + 1
	c.result = &res
	return &res, oldInSPI, nil
}

// IKE SA rekey (RFC 7296 section 2.18). An IKE SA has its own lifetime; before
// it expires it must be replaced, which — unlike a Child SA rekey — requires a
// fresh Diffie-Hellman exchange, so the new SA's control-plane keys have
// forward secrecy from the old one. The new IKE SA inherits every Child SA
// unchanged (their ESP keys are not re-derived), so the data path never pauses:
// only the IKE control channel's SPIs and SK_* keys rotate, and message IDs
// reset to zero on the new SA.
//
// RekeyIKE runs the whole make-before-break sequence as initiator:
//
//	CREATE_CHILD_SA{SA(new IKE proposal), Ni, KEi}  -->   (on the old SA)
//	                        <--  CREATE_CHILD_SA{SA, Nr, KEr}
//	INFORMATIONAL{D(IKE)}                            -->   (delete the old SA)
//	                        <--  INFORMATIONAL{}
//
// and only then swaps the client onto the new SPIs/keys. It requires Attach
// (post-handshake control mode) and serializes with DPD, Child rekey and MOBIKE
// roam via exchMu, so no other exchange sees the SA mid-swap.
func (c *Client) RekeyIKE(ctx context.Context) error {
	c.exchMu.Lock()
	defer c.exchMu.Unlock()

	if !c.attached.Load() {
		return errNotAttached
	}

	// Fresh DH keypair in the current group, a new nonce, and a new initiator
	// SPI for the replacement IKE SA.
	dh, err := transform.DH(c.suite.DHID)
	if err != nil {
		return fmt.Errorf("ike: rekey-IKE DH: %w", err)
	}
	pub, err := dh.Generate()
	if err != nil {
		return fmt.Errorf("ike: rekey-IKE DH generate: %w", err)
	}
	ni := mustNonce(32)
	newSPIi := newIKESPI()

	props := DefaultIKEProposals()
	for i := range props {
		props[i].SPI = u64BE(newSPIi)
	}
	b := payload.NewBuilder()
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: props}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(ni))
	b.Add(payload.TypeKE, false, payload.MarshalKE(payload.KEPayload{Group: c.suite.DHID, KeyData: pub}))

	msgID := c.sendMsgID
	pkts, err := c.seal(payload.CREATE_CHILD_SA, msgID, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKEAll(pkts); err != nil {
		return fmt.Errorf("ike: rekey-IKE send: %w", err)
	}
	inners, err := c.recvInnersFrom(c.recvControl(ctx))
	if err != nil {
		return fmt.Errorf("ike: rekey-IKE response: %w", err)
	}

	saPay := findInner(inners, payload.TypeSA)
	noncePay := findInner(inners, payload.TypeNonce)
	kePay := findInner(inners, payload.TypeKE)
	if saPay == nil || noncePay == nil || kePay == nil {
		return fmt.Errorf("ike: rekey-IKE response missing SA/Nonce/KE")
	}
	respSA, err := payload.ParseSA(saPay.Body)
	if err != nil {
		return fmt.Errorf("ike: rekey-IKE response SA: %w", err)
	}
	newSuite, _, err := SelectIKESuite(respSA)
	if err != nil {
		return fmt.Errorf("ike: rekey-IKE response suite: %w", err)
	}
	if len(respSA.Proposals) == 0 || len(respSA.Proposals[0].SPI) != 8 {
		return fmt.Errorf("ike: rekey-IKE response carried no responder SPI")
	}
	newSPIr := beU64(respSA.Proposals[0].SPI)
	nr := payload.ParseNonce(noncePay.Body)
	ke, err := payload.ParseKE(kePay.Body)
	if err != nil {
		return fmt.Errorf("ike: rekey-IKE response KE: %w", err)
	}
	if ke.Group != newSuite.DHID {
		return fmt.Errorf("ike: rekey-IKE response KE group %d != negotiated %d", ke.Group, newSuite.DHID)
	}
	shared, err := dh.ComputeSecret(ke.KeyData)
	if err != nil {
		return fmt.Errorf("ike: rekey-IKE shared secret: %w", err)
	}

	// New control-plane keys: SKEYSEED seeded from the *old* SK_d and the fresh
	// DH secret (RFC 7296 2.18), then the standard prf+ over the new SPIs.
	newKeys := DeriveRekeyedIKEKeys(newSuite.PRF, c.keys.SKd, shared, ni, nr,
		newSPIi, newSPIr, newSuite.encKeyLen(), newSuite.integKeyLen())

	// Delete the old IKE SA on the *old* SA (old SPIs/keys), before swapping.
	// The message ID after the CREATE_CHILD_SA on the old SA is msgID+1.
	if err := c.deleteOldIKESA(ctx, msgID+1); err != nil {
		return fmt.Errorf("ike: rekey-IKE delete old SA: %w", err)
	}

	// Swap the client onto the new IKE SA. Message IDs reset to zero: the delete
	// was the last exchange on the old SA, and the new SA starts fresh.
	c.mu.Lock()
	c.spiI = newSPIi
	c.spiR = newSPIr
	c.suite = newSuite
	c.keys = newKeys
	c.dh = dh
	c.ni, c.nr = ni, nr
	c.sendMsgID = 0
	c.mu.Unlock()
	return nil
}

// deleteOldIKESA sends a protected INFORMATIONAL Delete for the whole IKE SA
// (RFC 7296 3.11: Protocol=IKE, no SPIs) at msgID, using the client's current
// (old) SPIs and keys, and waits for the empty response. The caller holds
// exchMu; this must run before RekeyIKE swaps in the new SA.
func (c *Client) deleteOldIKESA(ctx context.Context, msgID uint32) error {
	b := payload.NewBuilder()
	b.Add(payload.TypeDelete, false, payload.MarshalDelete(payload.DeletePayload{
		Protocol: payload.ProtoIKE, SPISize: 0,
	}))
	pkts, err := c.seal(payload.INFORMATIONAL, msgID, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKEAll(pkts); err != nil {
		return fmt.Errorf("ike: delete-IKE send: %w", err)
	}
	if _, err := c.recvInnersFrom(c.recvControl(ctx)); err != nil {
		return fmt.Errorf("ike: delete-IKE response: %w", err)
	}
	return nil
}

// DeleteChildSA tears down a Child SA by its inbound SPI with a protected
// INFORMATIONAL Delete (RFC 7296 1.4.1). Called after a rekey swap has moved
// traffic to the replacement SA, so the old one can be retired.
func (c *Client) DeleteChildSA(ctx context.Context, inSPI uint32) error {
	c.exchMu.Lock()
	defer c.exchMu.Unlock()

	if !c.attached.Load() {
		return errNotAttached
	}
	b := payload.NewBuilder()
	b.Add(payload.TypeDelete, false, payload.MarshalDelete(payload.DeletePayload{
		Protocol: payload.ProtoESP, SPISize: 4, SPIs: [][]byte{u32BE(inSPI)},
	}))
	msgID := c.sendMsgID
	pkts, err := c.seal(payload.INFORMATIONAL, msgID, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKEAll(pkts); err != nil {
		return fmt.Errorf("ike: delete send: %w", err)
	}
	if _, err := c.recvInnersFrom(c.recvControl(ctx)); err != nil {
		return fmt.Errorf("ike: delete response: %w", err)
	}
	c.sendMsgID = msgID + 1
	return nil
}

// CurrentServerAddr returns the address ESP is currently sent to, so a rekeyed
// tunnel inherits the peer endpoint (which MOBIKE roam may have moved).
func (c *Client) CurrentServerAddr() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.result != nil && c.result.ServerAddr != nil {
		return c.result.ServerAddr
	}
	return c.conn.RemoteAddr().(*net.UDPAddr)
}
