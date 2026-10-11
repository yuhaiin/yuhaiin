package dtls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Config parameters one DTLS connection.
//
// It selects the key exchange by what is set: a PSK gives the AnyConnect
// pre-shared-key handshake, and a Certificate gives Fortinet's certificate-based
// ECDHE handshake. The two are never mixed on one connection.
type Config struct {
	// PSK is the pre-shared key. For AnyConnect it comes from an RFC 5705
	// exporter on the CSTP/TLS session, so it is already bound to that session.
	PSK []byte
	// PSKIdentity names the key. AnyConnect uses a fixed identity.
	PSKIdentity []byte
	// SessionID is placed in the ClientHello's session-id field. AnyConnect
	// carries the hex-decoded X-DTLS-App-ID here, which is how a server ties the
	// UDP flow back to the HTTPS session that authorised it.
	SessionID []byte

	// Certificate is the server's certificate and key for a certificate-based
	// (ECDHE-ECDSA) handshake. When set, the connection uses ECDHE rather than
	// PSK. It is ignored on a client.
	Certificate *tls.Certificate
	// InsecureSkipVerify, on a client, skips X.509 chain and hostname validation
	// of the server certificate. The ServerKeyExchange signature is still checked
	// against the presented certificate regardless -- that is what proves the
	// server holds the key -- so this relaxes only trust in the issuer.
	InsecureSkipVerify bool
	// VerifyPeerCertificate, on a client, receives the server's raw certificate
	// chain to pin or otherwise check it; a non-nil error aborts the handshake.
	VerifyPeerCertificate func(rawCerts [][]byte) error
	// ServerName is the expected certificate hostname, checked during chain
	// validation unless InsecureSkipVerify is set.
	ServerName string
	// RootCAs is the set of trust anchors chain validation uses; nil uses the
	// host's. A private gateway signed by a private CA is the ordinary case here.
	RootCAs *x509.CertPool

	// MTU bounds handshake fragments. Zero uses a conservative default.
	MTU int
	// HandshakeTimeout bounds the whole handshake.
	HandshakeTimeout time.Duration
}

// offeredSuites is the cipher-suite list a client offers, chosen by config: a
// PSK connection offers PSK suites, otherwise the certificate-based ECDHE suites.
func (c *Conn) offeredSuites() []suite {
	if len(c.cfg.PSK) == 0 {
		return ecdheSuites
	}
	return pskSuites
}

// serverSuites is what a server will accept, chosen the same way: a configured
// certificate means ECDHE, otherwise PSK.
func (c *Conn) serverSuites() []suite {
	if c.cfg.Certificate != nil {
		return ecdheSuites
	}
	return pskSuites
}

// retransmit backs off between flight retransmissions, doubling each time from
// the initial value, as RFC 6347 section 4.2.4.1 requires.
const (
	initialRetransmit = 1 * time.Second
	maxRetransmit     = 8 * time.Second
	defaultTimeout    = 20 * time.Second

	// defaultMTU bounds handshake *fragments*, not tunnel payloads — it is not
	// an inner MTU, and deriving it from an encapsulation overhead would be a
	// category error. A handshake has to complete across whatever path exists
	// before anything can be negotiated about that path, so this is deliberately
	// pessimistic: 1200 is the figure DTLS implementations converged on because
	// it survives IPv6's 1280-octet minimum link MTU with the outer headers
	// still to pay for. Config.MTU raises it when the path is known.
	defaultMTU = 1200
)

// Conn is an established DTLS connection carrying application datagrams. It
// wraps a net.Conn that must deliver whole datagrams — a connected UDP socket,
// or one side of a demultiplexing server.
//
// Read and Write are datagram-oriented: each Write becomes one record and each
// Read returns one record's payload, so unlike a stream there is no framing for
// the caller to do.
type Conn struct {
	conn net.Conn
	cfg  Config

	suite  suite
	master []byte

	// writeMu serializes record emission and the sequence counter it advances.
	writeMu  sync.Mutex
	writeSeq uint64
	writeEp  uint16
	out      *aeadState

	readMu  sync.Mutex
	in      *aeadState
	readEp  uint16
	replay  replayWindow
	pending [][]byte // decrypted application payloads not yet returned by Read
	readBuf []byte

	// deferred holds encrypted handshake records that arrived before the read
	// keys were installed, so they can be decrypted once the keys exist rather
	// than dropped. This happens when a peer coalesces its ClientKeyExchange,
	// ChangeCipherSpec and Finished into one datagram: the Finished is at the new
	// epoch, but the ClientKeyExchange that unlocks it is in the same datagram.
	deferred []deferredRecord
}

// deferredRecord is an encrypted record held until its keys are available.
type deferredRecord struct {
	typ      uint8
	version  uint16
	epoch    uint16
	sequence uint64
	fragment []byte
}

// Client performs a DTLS handshake in the client role and returns the
// established connection.
func Client(conn net.Conn, cfg Config) (*Conn, error) {
	c := &Conn{conn: conn, cfg: cfg}
	if err := c.clientHandshake(); err != nil {
		return nil, err
	}
	return c, nil
}

// Server performs a DTLS handshake in the server role. It answers the client's
// first ClientHello with a HelloVerifyRequest, so no state is kept for a peer
// that has not proven it can receive at its claimed address.
func Server(conn net.Conn, cfg Config) (*Conn, error) {
	c := &Conn{conn: conn, cfg: cfg}
	if err := c.serverHandshake(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Conn) mtu() int {
	if c.cfg.MTU > 0 {
		return c.cfg.MTU
	}
	return defaultMTU
}

func (c *Conn) timeout() time.Duration {
	if c.cfg.HandshakeTimeout > 0 {
		return c.cfg.HandshakeTimeout
	}
	return defaultTimeout
}

// Write sends one application datagram.
func (c *Conn) Write(b []byte) (int, error) {
	if len(b) > maxRecord {
		return 0, fmt.Errorf("dtls: datagram of %d octets exceeds the record limit", len(b))
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.out == nil {
		return 0, errors.New("dtls: connection is not established")
	}
	rec := c.buildRecordLocked(recordApplicationData, b)
	if _, err := c.conn.Write(rec); err != nil {
		return 0, err
	}
	return len(b), nil
}

// buildRecordLocked encrypts and frames one record. The caller holds writeMu.
func (c *Conn) buildRecordLocked(typ uint8, payload []byte) []byte {
	seq := c.writeSeq
	c.writeSeq++
	sealed := c.out.seal(typ, version1_2, c.writeEp, seq, payload)
	// Size the record buffer for the header plus the sealed payload so appending
	// the header and the sealed bytes does not reallocate.
	out := make([]byte, 0, recordHeaderLen+len(sealed))
	out = appendRecordHeader(out, typ, version1_2, c.writeEp, seq, len(sealed))
	return append(out, sealed...)
}

// Read returns the payload of the next application record.
func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if len(c.pending) > 0 {
			pkt := c.pending[0]
			c.pending = c.pending[1:]
			return copy(b, pkt), nil
		}
		if c.readBuf == nil {
			c.readBuf = make([]byte, maxRecord+recordHeaderLen+256)
		}
		n, err := c.conn.Read(c.readBuf)
		if err != nil {
			return 0, err
		}
		if err := c.processDatagram(c.readBuf[:n]); err != nil {
			// A close_notify is the peer ending the connection, and it decrypted,
			// so it is authentic and final.
			if errors.Is(err, errClosed) {
				return 0, io.EOF
			}
			// A record that fails to decrypt or replays is dropped, not fatal: on
			// an unreliable transport an attacker can always inject garbage, and
			// tearing the tunnel down for it would be the vulnerability.
			continue
		}
	}
}

// processDatagram decrypts every record in a datagram, queueing application
// payloads. It reports an error only when nothing usable was found.
func (c *Conn) processDatagram(buf []byte) error {
	var kept int
	for len(buf) > 0 {
		rec, n, err := parseRecord(buf)
		if err != nil {
			break
		}
		buf = buf[n:]
		if rec.epoch != c.readEp {
			continue
		}
		if err := c.replay.check(rec.sequence); err != nil {
			continue
		}
		plain, err := c.in.open(rec.typ, rec.version, rec.epoch, rec.sequence, rec.fragment)
		if err != nil {
			continue
		}
		switch rec.typ {
		case recordApplicationData:
			c.pending = append(c.pending, append([]byte(nil), plain...))
			kept++
		case recordAlert:
			if len(plain) >= 2 && plain[1] == alertCloseNotify {
				return errClosed
			}
		}
	}
	if kept == 0 {
		return errors.New("dtls: datagram carried no application data")
	}
	return nil
}

var errClosed = errors.New("dtls: peer closed the connection")

// Close sends a close_notify and closes the underlying connection.
func (c *Conn) Close() error {
	c.writeMu.Lock()
	if c.out != nil {
		rec := c.buildRecordLocked(recordAlert, []byte{alertWarning, alertCloseNotify})
		_, _ = c.conn.Write(rec)
	}
	c.writeMu.Unlock()
	return c.conn.Close()
}

// LocalAddr and RemoteAddr expose the underlying connection's addresses.
func (c *Conn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline and friends pass through to the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// CipherSuite reports the negotiated suite, for logging.
func (c *Conn) CipherSuite() uint16 { return c.suite.id }

// --- handshake plumbing shared by both roles ---

// handshakeState tracks a handshake in progress.
type handshakeState struct {
	transcript []byte // every handshake message, unfragmented, in order
	sendSeq    uint16
	reasm      *reassembler
	clientRand []byte
	serverRand []byte
}

func newHandshakeState() *handshakeState {
	return &handshakeState{reasm: newReassembler()}
}

// record appends a message to the transcript that Finished authenticates.
func (h *handshakeState) record(m handshakeMsg) {
	h.transcript = append(h.transcript, m.marshal()...)
}

// sendFlight transmits a set of handshake messages as plaintext records,
// fragmenting each to the MTU.
func (c *Conn) sendFlight(hs *handshakeState, msgs []handshakeMsg) ([]byte, error) {
	var datagram []byte
	for _, m := range msgs {
		for _, frag := range m.fragments(c.mtu() - recordHeaderLen) {
			datagram = appendRecordHeader(datagram, recordHandshake, version1_2, 0, c.writeSeq, len(frag))
			datagram = append(datagram, frag...)
			c.writeSeq++
		}
	}
	if _, err := c.conn.Write(datagram); err != nil {
		return nil, err
	}
	return datagram, nil
}

// sendRaw retransmits a previously built flight verbatim.
func (c *Conn) sendRaw(datagram []byte) error {
	_, err := c.conn.Write(datagram)
	return err
}

// readFlight reads records until want is satisfied by the messages received, or
// the deadline expires. It retransmits the last flight on each timeout, which is
// how DTLS recovers from loss without any acknowledgements of its own.
func (c *Conn) readFlight(hs *handshakeState, lastFlight []byte, want func([]handshakeMsg) bool) ([]handshakeMsg, error) {
	deadline := time.Now().Add(c.timeout())
	backoff := initialRetransmit
	var collected []handshakeMsg
	buf := make([]byte, maxRecord+recordHeaderLen+256)

	for time.Now().Before(deadline) {
		if err := c.conn.SetReadDeadline(time.Now().Add(backoff)); err != nil {
			return nil, err
		}
		n, err := c.conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if lastFlight != nil {
					if err := c.sendRaw(lastFlight); err != nil {
						return nil, err
					}
				}
				backoff = min(backoff*2, maxRetransmit)
				continue
			}
			return nil, err
		}
		msgs, err := c.consumeHandshake(hs, buf[:n])
		if err != nil {
			return nil, err
		}
		collected = append(collected, msgs...)
		if want(collected) {
			_ = c.conn.SetReadDeadline(time.Time{})
			return collected, nil
		}
	}
	return nil, errors.New("dtls: handshake timed out")
}

// consumeHandshake decodes the handshake fragments in a datagram. Records in the
// handshake are plaintext until the epoch advances, and ChangeCipherSpec is
// surfaced as a pseudo-message so the caller can order the key change correctly.
func (c *Conn) consumeHandshake(hs *handshakeState, buf []byte) ([]handshakeMsg, error) {
	var out []handshakeMsg
	for len(buf) > 0 {
		rec, n, err := parseRecord(buf)
		if err != nil {
			break
		}
		buf = buf[n:]

		payload := rec.fragment
		if rec.epoch != 0 {
			// Encrypted: the peer has already changed cipher spec, so this is its
			// Finished.
			if c.in == nil {
				// The keys are not installed yet. A peer that coalesces its
				// ClientKeyExchange and Finished into one datagram lands here for
				// the Finished; hold it rather than drop it, so it can be
				// decrypted once the ClientKeyExchange in this same datagram has
				// installed the keys. drainDeferred replays it then.
				c.deferred = append(c.deferred, deferredRecord{
					typ:      rec.typ,
					version:  rec.version,
					epoch:    rec.epoch,
					sequence: rec.sequence,
					fragment: append([]byte(nil), rec.fragment...),
				})
				continue
			}
			if err := c.replay.check(rec.sequence); err != nil {
				continue
			}
			payload, err = c.in.open(rec.typ, rec.version, rec.epoch, rec.sequence, rec.fragment)
			if err != nil {
				return nil, fmt.Errorf("dtls: decrypting the peer's Finished: %w", err)
			}
		}

		msgs, err := c.dispatchRecord(hs, rec.typ, payload)
		if err != nil {
			return nil, err
		}
		out = append(out, msgs...)
	}
	return out, nil
}

// dispatchRecord turns one decrypted record's payload into handshake messages:
// a ChangeCipherSpec becomes its pseudo-message, a fatal alert is an error, and
// a handshake record is split into fragments and fed to the reassembler.
func (c *Conn) dispatchRecord(hs *handshakeState, typ uint8, payload []byte) ([]handshakeMsg, error) {
	var out []handshakeMsg
	switch typ {
	case recordChangeCipherSpec:
		out = append(out, handshakeMsg{typ: pseudoChangeCipherSpec})
	case recordAlert:
		if len(payload) >= 2 && payload[0] == alertFatal {
			return nil, fmt.Errorf("dtls: peer sent fatal alert %d", payload[1])
		}
	case recordHandshake:
		for len(payload) > 0 {
			fh, err := parseFragment(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[fh.consumed:]
			ready, err := hs.reasm.accept(fh)
			if err != nil {
				return nil, err
			}
			out = append(out, ready...)
		}
	}
	return out, nil
}

// drainDeferred decrypts and processes the encrypted records that were held for
// want of keys, returning the handshake messages they carried. It is called once
// the read keys are installed, so a Finished that shared a datagram with the
// ClientKeyExchange is recovered rather than lost.
func (c *Conn) drainDeferred(hs *handshakeState) ([]handshakeMsg, error) {
	if len(c.deferred) == 0 {
		return nil, nil
	}
	var out []handshakeMsg
	for _, rec := range c.deferred {
		if err := c.replay.check(rec.sequence); err != nil {
			continue
		}
		payload, err := c.in.open(rec.typ, rec.version, rec.epoch, rec.sequence, rec.fragment)
		if err != nil {
			return nil, fmt.Errorf("dtls: decrypting a deferred record: %w", err)
		}
		msgs, err := c.dispatchRecord(hs, rec.typ, payload)
		if err != nil {
			return nil, err
		}
		out = append(out, msgs...)
	}
	c.deferred = nil
	return out, nil
}

// pseudoChangeCipherSpec marks a ChangeCipherSpec in the message stream. It is
// not a handshake message — it has its own record type and no handshake header —
// but the flight logic needs to see it in order, and no real handshake type
// collides with this value.
const pseudoChangeCipherSpec uint8 = 0xff

// changeCipherSpec sends the CCS record and installs the new write keys.
func (c *Conn) changeCipherSpec(out *aeadState) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	rec := appendRecordHeader(nil, recordChangeCipherSpec, version1_2, c.writeEp, c.writeSeq, 1)
	rec = append(rec, 1)
	c.writeSeq++
	if _, err := c.conn.Write(rec); err != nil {
		return err
	}
	c.writeEp++
	c.writeSeq = 0
	c.out = out
	return nil
}

// installReadKeys switches the read side to the new epoch.
func (c *Conn) installReadKeys(in *aeadState) {
	c.in = in
	c.readEp++
	c.replay = replayWindow{}
}

// findMsg returns the first message of a type from a collected flight.
func findMsg(msgs []handshakeMsg, typ uint8) (handshakeMsg, bool) {
	for _, m := range msgs {
		if m.typ == typ {
			return m, true
		}
	}
	return handshakeMsg{}, false
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("dtls: entropy: %w", err)
	}
	return b, nil
}

// newRandom builds a ClientHello/ServerHello random. RFC 5246 puts a timestamp
// in the first four octets; modern practice (RFC 8446 and every current stack)
// is 32 fully random octets, which leaks nothing about the host clock.
func newRandom() ([]byte, error) { return randomBytes(randomLen) }

// cookieMAC derives a stateless HelloVerifyRequest cookie from the client's
// address, keyed by a per-server secret. Deriving rather than storing is the
// point of the mechanism: the server can verify the cookie it gets back without
// having allocated anything when it issued it.
func cookieMAC(secret, addr []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(addr)
	return mac.Sum(nil)[:16]
}

func constantTimeEqual(a, b []byte) bool { return hmac.Equal(a, b) }

// verifyFinished checks a peer's Finished against the transcript.
func verifyFinished(s suite, master []byte, label string, transcript, got []byte) error {
	want := finishedVerifyData(s, master, label, transcript)
	if !constantTimeEqual(want, got) {
		return errors.New("dtls: Finished verification failed (wrong pre-shared key?)")
	}
	return nil
}
