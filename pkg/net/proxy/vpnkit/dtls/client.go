package dtls

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// clientHandshake runs the PSK handshake in the client role:
//
//	-> ClientHello
//	<- HelloVerifyRequest (cookie)
//	-> ClientHello (with cookie)
//	<- ServerHello, [ServerKeyExchange], ServerHelloDone
//	-> ClientKeyExchange, ChangeCipherSpec, Finished
//	<- ChangeCipherSpec, Finished
func (c *Conn) clientHandshake() error {
	hs := newHandshakeState()

	random, err := newRandom()
	if err != nil {
		return err
	}
	hs.clientRand = random

	hello := clientHello{
		version:      version1_2,
		random:       random,
		sessionID:    c.cfg.SessionID,
		cipherSuites: c.offeredSuiteIDs(),
	}

	// Flight 1: ClientHello with no cookie. The server is expected to answer with
	// a HelloVerifyRequest, but a server configured not to may go straight to
	// ServerHello, so both are accepted.
	msg := handshakeMsg{typ: handshakeClientHello, seq: hs.sendSeq, body: hello.marshal()}
	flight, err := c.sendFlight(hs, []handshakeMsg{msg})
	if err != nil {
		return err
	}
	hs.sendSeq++

	got, err := c.readFlight(hs, flight, func(msgs []handshakeMsg) bool {
		_, hvr := findMsg(msgs, handshakeHelloVerifyReq)
		_, done := findMsg(msgs, handshakeServerHelloDone)
		return hvr || done
	})
	if err != nil {
		return err
	}

	// Flight 2: repeat the ClientHello carrying the cookie. Per RFC 6347 the
	// HelloVerifyRequest and the two ClientHellos are excluded from the
	// transcript, so the hash is started fresh from the second ClientHello.
	if hvr, ok := findMsg(got, handshakeHelloVerifyReq); ok {
		verify, err := parseHelloVerifyRequest(hvr.body)
		if err != nil {
			return err
		}
		hello.cookie = verify.cookie
		msg = handshakeMsg{typ: handshakeClientHello, seq: hs.sendSeq, body: hello.marshal()}
		flight, err = c.sendFlight(hs, []handshakeMsg{msg})
		if err != nil {
			return err
		}
		hs.sendSeq++

		got, err = c.readFlight(hs, flight, func(msgs []handshakeMsg) bool {
			_, done := findMsg(msgs, handshakeServerHelloDone)
			return done
		})
		if err != nil {
			return err
		}
	}
	hs.record(msg)

	sh, ok := findMsg(got, handshakeServerHello)
	if !ok {
		return errors.New("dtls: server never sent a ServerHello")
	}
	hello2, err := parseServerHello(sh.body)
	if err != nil {
		return err
	}
	s, err := suiteByID(hello2.cipherSuite)
	if err != nil {
		return err
	}
	c.suite = s
	hs.serverRand = hello2.random

	// Record the server's flight in the order it was sent. Certificate is present
	// only for ECDHE; findMsg skips it otherwise.
	for _, typ := range []uint8{handshakeServerHello, handshakeCertificate, handshakeServerKeyExchange, handshakeServerHelloDone} {
		if m, ok := findMsg(got, typ); ok {
			hs.record(m)
		}
	}

	// Flight 3: ClientKeyExchange (PSK identity or an ECDHE key share),
	// ChangeCipherSpec, Finished.
	var cke handshakeMsg
	var premaster []byte
	if s.kx == kxECDHE {
		ske, err := c.processServerECDHE(got, hs)
		if err != nil {
			return err
		}
		priv, pubBytes, err := newECDHEKey()
		if err != nil {
			return err
		}
		cke = handshakeMsg{typ: handshakeClientKeyExchange, seq: hs.sendSeq, body: marshalECDHEClientKeyExchange(pubBytes)}
		if premaster, err = ecdhePremaster(priv, ske.pubkey); err != nil {
			return err
		}
	} else {
		cke = handshakeMsg{typ: handshakeClientKeyExchange, seq: hs.sendSeq, body: pskClientKeyExchange{identity: c.cfg.PSKIdentity}.marshal()}
		premaster = pskPremaster(c.cfg.PSK)
	}
	hs.sendSeq++
	hs.record(cke)

	master := masterSecret(s.prfHash, premaster, hs.clientRand, hs.serverRand)
	c.master = master
	km := expandKeys(s, master, hs.clientRand, hs.serverRand)

	writeAEAD, err := newAEAD(km.clientKey, km.clientIV)
	if err != nil {
		return err
	}
	readAEAD, err := newAEAD(km.serverKey, km.serverIV)
	if err != nil {
		return err
	}

	// The client's Finished covers everything through its own ClientKeyExchange.
	verifyData := finishedVerifyData(s, master, labelClientFinished, hs.transcript)
	fin := handshakeMsg{typ: handshakeFinished, seq: hs.sendSeq, body: verifyData}
	hs.sendSeq++
	hs.record(fin)

	if _, err := c.sendFlight(hs, []handshakeMsg{cke}); err != nil {
		return err
	}
	if err := c.changeCipherSpec(writeAEAD); err != nil {
		return err
	}
	if err := c.sendEncryptedHandshake(fin); err != nil {
		return err
	}

	// Flight 4: the server's ChangeCipherSpec and Finished. Its Finished covers
	// the transcript including ours.
	c.installReadKeys(readAEAD)
	got, err = c.readFlight(hs, nil, func(msgs []handshakeMsg) bool {
		_, ok := findMsg(msgs, handshakeFinished)
		return ok
	})
	if err != nil {
		return err
	}
	serverFin, ok := findMsg(got, handshakeFinished)
	if !ok {
		return errors.New("dtls: server never sent Finished")
	}
	if err := verifyFinished(s, master, labelServerFinished, hs.transcript, serverFin.body); err != nil {
		return err
	}
	return nil
}

// processServerECDHE validates the server's Certificate and ECDHE
// ServerKeyExchange from an ECDHE flight: it checks the certificate (chain and
// hostname unless skipped, plus any pin), then verifies the key-share signature
// against that certificate. The signature check happens regardless of
// InsecureSkipVerify -- it is what proves the peer holds the key, independent of
// whether its issuer is trusted.
func (c *Conn) processServerECDHE(got []handshakeMsg, hs *handshakeState) (serverKeyExchangeECDHE, error) {
	certMsg, ok := findMsg(got, handshakeCertificate)
	if !ok {
		return serverKeyExchangeECDHE{}, errors.New("dtls: server sent no Certificate")
	}
	chain, err := parseCertificate(certMsg.body)
	if err != nil {
		return serverKeyExchangeECDHE{}, err
	}
	if err := c.verifyServerCertificate(chain); err != nil {
		return serverKeyExchangeECDHE{}, err
	}

	skeMsg, ok := findMsg(got, handshakeServerKeyExchange)
	if !ok {
		return serverKeyExchangeECDHE{}, errors.New("dtls: server sent no ServerKeyExchange")
	}
	ske, err := parseECDHEServerKeyExchange(skeMsg.body)
	if err != nil {
		return serverKeyExchangeECDHE{}, err
	}
	if err := verifyECDHESignature(chain[0], hs.clientRand, hs.serverRand, ske); err != nil {
		return serverKeyExchangeECDHE{}, err
	}
	return ske, nil
}

// verifyServerCertificate applies the caller's trust policy to the server's
// certificate chain: a pin callback if set, then X.509 chain and hostname
// validation unless InsecureSkipVerify.
func (c *Conn) verifyServerCertificate(chain [][]byte) error {
	if c.cfg.VerifyPeerCertificate != nil {
		if err := c.cfg.VerifyPeerCertificate(chain); err != nil {
			return err
		}
	}
	if c.cfg.InsecureSkipVerify {
		return nil
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return fmt.Errorf("dtls: parsing server certificate: %w", err)
	}
	roots := c.cfg.RootCAs
	if roots == nil {
		roots, _ = x509.SystemCertPool()
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	intermediates := x509.NewCertPool()
	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		if i > 0 {
			intermediates.AddCert(cert)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: c.cfg.ServerName})
	return err
}

// sendEncryptedHandshake emits a handshake message under the new write keys,
// which is how Finished is protected.
func (c *Conn) sendEncryptedHandshake(m handshakeMsg) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.out == nil {
		return fmt.Errorf("dtls: no write keys installed")
	}
	rec := c.buildRecordLocked(recordHandshake, m.marshal())
	_, err := c.conn.Write(rec)
	return err
}

// offeredSuiteIDs is the cipher suite list this client offers, chosen by config.
func (c *Conn) offeredSuiteIDs() []uint16 {
	list := c.offeredSuites()
	out := make([]uint16, 0, len(list))
	for _, s := range list {
		out = append(out, s.id)
	}
	return out
}
