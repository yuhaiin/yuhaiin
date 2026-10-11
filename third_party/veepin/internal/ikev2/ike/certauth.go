package ike

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"slices"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// Certificate authentication (RFC 7296 §2.15 with digital signatures, and
// RFC 7427 for the modern "Digital Signature" method). An endpoint proves its
// identity by signing the same AuthOctets that PSK authentication MACs — the
// first message plus the peer's nonce plus prf(SK_p, ID) — but with the private
// key of an X.509 certificate the peer can chain to a trusted CA.
//
// Two on-the-wire signature methods are produced:
//
//   - AUTH method 14 (RFC 7427 Digital Signature): the preferred path. The AUTH
//     payload carries a one-octet ASN.1 length, a DER AlgorithmIdentifier naming
//     the exact scheme (e.g. sha256WithRSAEncryption or ecdsa-with-SHA256), then
//     the signature. Both peers must have exchanged SIGNATURE_HASH_ALGORITHMS in
//     IKE_SA_INIT. This is what current strongSwan, Windows and Azure negotiate.
//   - AUTH method 1 (RSA Digital Signature): a legacy fallback for a peer that
//     did not offer RFC 7427 — RSASSA-PKCS1-v1_5 over the SHA-1 digest of the
//     octets, the signature alone in the AUTH payload.
//
// The classic per-curve ECDSA methods (9/10/11) are not produced; a peer that
// cannot do RFC 7427 gets the RSA fallback only.

// certCredential is a local certificate identity used to authenticate: the
// leaf certificate (and any intermediates) to present in CERT payloads, plus
// the private key to sign with.
type certCredential struct {
	leaf   *x509.Certificate
	chain  [][]byte      // DER of leaf first, then intermediates, for CERT payloads
	signer crypto.Signer // the leaf's private key
}

// newCertCredential builds a credential from a leaf certificate, its DER chain
// (leaf first) and a private key. The key must match the leaf's public key.
func newCertCredential(leaf *x509.Certificate, chain [][]byte, key crypto.PrivateKey) (*certCredential, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ike: certificate key does not implement crypto.Signer")
	}
	switch signer.Public().(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, *mldsa.PublicKey:
	default:
		return nil, fmt.Errorf("ike: unsupported certificate key type %T", signer.Public())
	}
	return &certCredential{leaf: leaf, chain: chain, signer: signer}, nil
}

// credentialFromTLS adapts a crypto/tls certificate (DER chain leaf-first plus a
// private key) into a certCredential, so callers configure cert auth with the
// same familiar type they use for any other TLS server.
func credentialFromTLS(c *tls.Certificate) (*certCredential, error) {
	if c == nil || len(c.Certificate) == 0 {
		return nil, fmt.Errorf("ike: certificate has no DER chain")
	}
	leaf := c.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return nil, fmt.Errorf("ike: parse leaf certificate: %w", err)
		}
	}
	return newCertCredential(leaf, c.Certificate, c.PrivateKey)
}

// sigHashList is the set of hashes veepin advertises in (and accepts from) a
// SIGNATURE_HASH_ALGORITHMS notify, strongest first.
//
// HashIdentity is first because it is the only one ML-DSA can use: ML-DSA
// hashes the message itself, so "no external hash" is not a weaker option in
// this list but a different kind of entry. Advertising it is what lets a peer
// select ML-DSA at all (draft-ietf-ipsecme-ikev2-pqc-auth), and it costs a
// classical peer nothing -- it simply picks a SHA-2 entry as before.
var sigHashList = []uint16{payload.HashIdentity, payload.HashSHA512, payload.HashSHA384, payload.HashSHA256}

// addSigHashNotify appends a SIGNATURE_HASH_ALGORITHMS notify (RFC 7427 §4) to
// an IKE_SA_INIT builder, advertising the hashes we will use for a method-14
// Digital Signature.
func addSigHashNotify(b *payload.Builder) {
	data := make([]byte, 0, 2*len(sigHashList))
	for _, h := range sigHashList {
		data = append(data, byte(h>>8), byte(h))
	}
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.SignatureHashAlgorithms, Data: data,
	}))
}

// findSigHashes returns the hash IDs the peer advertised in a
// SIGNATURE_HASH_ALGORITHMS notify among the given IKE_SA_INIT payloads, or nil.
func findSigHashes(payloads []payload.RawPayload) []uint16 {
	for _, p := range payloads {
		if p.Type != payload.TypeNotify {
			continue
		}
		n, err := payload.ParseNotify(p.Body)
		if err != nil || n.Type != payload.SignatureHashAlgorithms {
			continue
		}
		var hs []uint16
		for i := 0; i+2 <= len(n.Data); i += 2 {
			hs = append(hs, uint16(n.Data[i])<<8|uint16(n.Data[i+1]))
		}
		return hs
	}
	return nil
}

// signAuth produces an AUTH payload for a certificate credential over
// authOctets, preferring the RFC 7427 Digital Signature (method 14) when the
// peer advertised SIGNATURE_HASH_ALGORITHMS and falling back to the legacy RSA
// method otherwise.
func signAuth(cred *certCredential, authOctets []byte, peerHashes []uint16) (payload.AuthMethod, []byte, error) {
	if len(peerHashes) > 0 {
		return signAuthDigital(cred, authOctets, peerHashes)
	}
	return signAuthRSALegacy(cred, authOctets)
}

// requirePostQuantumKey rejects a peer public key that is not ML-DSA.
//
// It is separate from verifyAuth because the check is about WHICH key was
// presented rather than whether the signature is good: a perfectly valid ECDSA
// signature is still a classical authentication, and under pq-ikev2 that is the
// thing being refused.
func requirePostQuantumKey(pub crypto.PublicKey) error {
	if _, ok := pub.(*mldsa.PublicKey); !ok {
		return fmt.Errorf("ike: peer authenticated with a %T key; this server requires "+
			"ML-DSA (FIPS 204)", pub)
	}
	return nil
}

// verifyAuth checks a peer's AUTH payload (method 14 or legacy RSA) against its
// certificate's public key.
func verifyAuth(pub crypto.PublicKey, method payload.AuthMethod, authOctets, data []byte) error {
	switch method {
	case payload.AuthDigitalSig:
		return verifyAuthDigital(pub, authOctets, data)
	case payload.AuthRSASig:
		return verifyAuthRSALegacy(pub, authOctets, data)
	default:
		return fmt.Errorf("ike: unsupported certificate AUTH method %d", method)
	}
}

// sigAlg names a concrete RFC 7427 signature scheme: the DER AlgorithmIdentifier
// that goes in the AUTH payload, the hash to digest the signed octets with, and
// whether it is an RSA or ECDSA scheme.
type sigAlg struct {
	hashID uint16
	// hash is the external digest applied before signing, or crypto.Hash(0)
	// for a scheme that hashes the message itself (ML-DSA).
	hash   crypto.Hash
	algID  []byte // DER AlgorithmIdentifier
	family sigFamily
	// params, for ML-DSA, is the parameter set the algID names. Verification
	// needs it to reconstruct a public key from raw bytes.
	params mldsa.Parameters
}

// sigFamily is which asymmetric family a scheme belongs to.
//
// This was an isRSA bool while there were two families. Three do not fit in a
// bool, and the failure mode of extending it rather than replacing it is that
// `isRSA == false` comes to mean "ECDSA or ML-DSA, look elsewhere" -- code that
// compiles, passes, and is wrong to read.
type sigFamily uint8

const (
	famRSA sigFamily = iota
	famECDSA
	famMLDSA
)

// DER AlgorithmIdentifier objects (RFC 5754 / RFC 5758). Each is a full
// SEQUENCE as it appears in an X.509 signatureAlgorithm field, which is exactly
// what an RFC 7427 AUTH payload carries.
var (
	algRSASHA256 = []byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00}
	algRSASHA384 = []byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00}
	algRSASHA512 = []byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00}
	algECDSA256  = []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}
	algECDSA384  = []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}
	algECDSA512  = []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04}

	// ML-DSA (FIPS 204), for draft-ietf-ipsecme-ikev2-pqc-auth. The OIDs are
	// 2.16.840.1.101.3.4.3.{17,18,19} and these byte strings were extracted from
	// certificates crypto/x509 actually minted, not transcribed from the draft.
	//
	// Note the length: THIRTEEN octets, with the parameters field ABSENT. The
	// RSA entries above are fifteen because they carry an explicit NULL. Copying
	// the RSA shape and appending 0x05 0x00 produces an identifier no peer
	// recognises, and lookupSigAlg compares with bytes.Equal, so the failure is
	// a clean "unrecognized signature AlgorithmIdentifier" rather than a silent
	// mismatch. TestMLDSAAlgorithmIdentifiersHaveAbsentParameters pins it.
	algMLDSA44 = []byte{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11}
	algMLDSA65 = []byte{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}
	algMLDSA87 = []byte{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13}
)

// knownSigAlgs is the set of RFC 7427 schemes veepin signs and verifies with.
var knownSigAlgs = []sigAlg{
	{payload.HashSHA256, crypto.SHA256, algRSASHA256, famRSA, mldsa.Parameters{}},
	{payload.HashSHA384, crypto.SHA384, algRSASHA384, famRSA, mldsa.Parameters{}},
	{payload.HashSHA512, crypto.SHA512, algRSASHA512, famRSA, mldsa.Parameters{}},
	{payload.HashSHA256, crypto.SHA256, algECDSA256, famECDSA, mldsa.Parameters{}},
	{payload.HashSHA384, crypto.SHA384, algECDSA384, famECDSA, mldsa.Parameters{}},
	{payload.HashSHA512, crypto.SHA512, algECDSA512, famECDSA, mldsa.Parameters{}},
	{payload.HashIdentity, 0, algMLDSA44, famMLDSA, mldsa.MLDSA44()},
	{payload.HashIdentity, 0, algMLDSA65, famMLDSA, mldsa.MLDSA65()},
	{payload.HashIdentity, 0, algMLDSA87, famMLDSA, mldsa.MLDSA87()},
}

// lookupSigAlg matches a DER AlgorithmIdentifier from a received AUTH payload to
// a known scheme.
func lookupSigAlg(algID []byte) (sigAlg, bool) {
	for _, a := range knownSigAlgs {
		if bytes.Equal(a.algID, algID) {
			return a, true
		}
	}
	return sigAlg{}, false
}

// chooseSigAlg picks the RFC 7427 scheme to sign with: the right family for the
// key, at the strongest hash the peer will accept (peerHashes, from its
// SIGNATURE_HASH_ALGORITHMS notify) that also suits the key. For ECDSA the hash
// is matched to the curve; for RSA SHA-256 is the floor.
func chooseSigAlg(pub crypto.PublicKey, peerHashes []uint16) (sigAlg, error) {
	var fam sigFamily
	pref := []uint16{payload.HashSHA256, payload.HashSHA384, payload.HashSHA512}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		fam = famRSA
	case *mldsa.PublicKey:
		// ML-DSA hashes the message internally, so the only acceptable "hash"
		// is the Identity hash -- and the peer must have said it accepts it. A
		// peer that advertised only SHA-2 gets a clean failure here rather than
		// a signature it will reject. This arm returns directly: there is one
		// scheme per parameter set, so there is nothing for the loop below to
		// choose between.
		for _, a := range knownSigAlgs {
			if a.family == famMLDSA && a.params == k.Parameters() {
				if len(peerHashes) > 0 && !slices.Contains(peerHashes, payload.HashIdentity) {
					return sigAlg{}, fmt.Errorf(
						"ike: peer does not accept the Identity hash, which ML-DSA requires (RFC 9593)")
				}
				return a, nil
			}
		}
		return sigAlg{}, fmt.Errorf("ike: unsupported ML-DSA parameter set %v", k.Parameters())
	case *ecdsa.PublicKey:
		// Match the hash to the curve (FIPS 186-4): P-256→SHA-256, etc. Fall
		// back through weaker hashes if the peer will not take the ideal one.
		switch k.Curve.Params().BitSize {
		case 521:
			pref = []uint16{payload.HashSHA512, payload.HashSHA384, payload.HashSHA256}
		case 384:
			pref = []uint16{payload.HashSHA384, payload.HashSHA512, payload.HashSHA256}
		default:
			pref = []uint16{payload.HashSHA256, payload.HashSHA384, payload.HashSHA512}
		}
		fam = famECDSA
	default:
		return sigAlg{}, fmt.Errorf("ike: unsupported key type %T", pub)
	}
	for _, want := range pref {
		if len(peerHashes) > 0 && !slices.Contains(peerHashes, want) {
			continue
		}
		for _, a := range knownSigAlgs {
			if a.family == fam && a.hashID == want {
				return a, nil
			}
		}
	}
	return sigAlg{}, fmt.Errorf("ike: no signature-hash algorithm in common with peer")
}

// signAuthDigital produces an RFC 7427 (method 14) AUTH payload value over
// authOctets, choosing a scheme for the credential's key and the peer's
// advertised hashes.
func signAuthDigital(cred *certCredential, authOctets []byte, peerHashes []uint16) (payload.AuthMethod, []byte, error) {
	alg, err := chooseSigAlg(cred.signer.Public(), peerHashes)
	if err != nil {
		return 0, nil, err
	}
	// ML-DSA takes the message, not a digest, and signals that with a nil
	// SignerOpts whose HashFunc is zero. Pre-hashing it would produce a
	// signature over the wrong input that verifies against nothing.
	signed, opts := authOctets, crypto.SignerOpts(alg.hash)
	if alg.family != famMLDSA {
		signed = hashOctets(alg.hash, authOctets)
	} else {
		opts = &mldsa.Options{}
	}
	sig, err := cred.signer.Sign(rand.Reader, signed, opts)
	if err != nil {
		return 0, nil, fmt.Errorf("ike: signing AUTH: %w", err)
	}
	// AUTH data: 1-octet ASN.1 length | AlgorithmIdentifier | signature.
	data := make([]byte, 0, 1+len(alg.algID)+len(sig))
	data = append(data, byte(len(alg.algID)))
	data = append(data, alg.algID...)
	data = append(data, sig...)
	return payload.AuthDigitalSig, data, nil
}

// verifyAuthDigital checks an RFC 7427 (method 14) AUTH payload against a peer
// certificate's public key.
func verifyAuthDigital(pub crypto.PublicKey, authOctets, data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("ike: empty digital-signature AUTH")
	}
	algLen := int(data[0])
	if 1+algLen > len(data) {
		return fmt.Errorf("ike: digital-signature AUTH truncated")
	}
	algID := data[1 : 1+algLen]
	sig := data[1+algLen:]
	alg, ok := lookupSigAlg(algID)
	if !ok {
		return fmt.Errorf("ike: unrecognized signature AlgorithmIdentifier")
	}
	switch p := pub.(type) {
	case *rsa.PublicKey:
		if alg.family != famRSA {
			return fmt.Errorf("ike: RSA key but non-RSA signature algorithm")
		}
		if err := rsa.VerifyPKCS1v15(p, alg.hash, hashOctets(alg.hash, authOctets), sig); err != nil {
			return fmt.Errorf("ike: RSA signature verify failed: %w", err)
		}
	case *ecdsa.PublicKey:
		if alg.family != famECDSA {
			return fmt.Errorf("ike: ECDSA key but non-ECDSA signature algorithm")
		}
		if !ecdsa.VerifyASN1(p, hashOctets(alg.hash, authOctets), sig) {
			return fmt.Errorf("ike: ECDSA signature verify failed")
		}
	case *mldsa.PublicKey:
		if alg.family != famMLDSA {
			return fmt.Errorf("ike: ML-DSA key but non-ML-DSA signature algorithm")
		}
		if p.Parameters() != alg.params {
			return fmt.Errorf("ike: AUTH names %v but the certificate holds %v",
				alg.params, p.Parameters())
		}
		// Over the octets themselves: ML-DSA does its own hashing.
		if err := mldsa.Verify(p, authOctets, sig, &mldsa.Options{}); err != nil {
			return fmt.Errorf("ike: ML-DSA signature verify failed: %w", err)
		}
	default:
		return fmt.Errorf("ike: unsupported peer key type %T", pub)
	}
	return nil
}

// signAuthRSALegacy produces a classic AUTH method 1 value: RSASSA-PKCS1-v1_5
// over the SHA-1 digest of the octets (RFC 7296 §3.8), signature only.
func signAuthRSALegacy(cred *certCredential, authOctets []byte) (payload.AuthMethod, []byte, error) {
	key, ok := cred.signer.(*rsa.PrivateKey)
	if !ok {
		return 0, nil, fmt.Errorf("ike: legacy RSA AUTH needs an RSA key, have %T", cred.signer)
	}
	sum := sha1.Sum(authOctets)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
	if err != nil {
		return 0, nil, fmt.Errorf("ike: legacy RSA signing: %w", err)
	}
	return payload.AuthRSASig, sig, nil
}

// verifyAuthRSALegacy checks a classic AUTH method 1 value.
func verifyAuthRSALegacy(pub crypto.PublicKey, authOctets, sig []byte) error {
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("ike: legacy RSA AUTH but peer key is %T", pub)
	}
	sum := sha1.Sum(authOctets)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA1, sum[:], sig); err != nil {
		return fmt.Errorf("ike: legacy RSA signature verify failed: %w", err)
	}
	return nil
}

// hashOctets returns h(authOctets).
func hashOctets(h crypto.Hash, authOctets []byte) []byte {
	hh := h.New()
	hh.Write(authOctets)
	return hh.Sum(nil)
}

// verifyPeerCertChain parses the peer's leaf certificate and any intermediates,
// verifies the chain to a trusted root, and returns the leaf. roots must be
// non-nil (an empty pool trusts nothing, which fails closed).
func verifyPeerCertChain(leafDER []byte, intermediateDER [][]byte, roots *x509.CertPool) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("ike: parse peer certificate: %w", err)
	}
	inter := x509.NewCertPool()
	for _, d := range intermediateDER {
		if c, err := x509.ParseCertificate(d); err == nil {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		// IKEv2 peer certs may or may not carry an EKU; accept any so a plain
		// CA-issued leaf is not rejected for lacking id-kp-ipsecIKE.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("ike: peer certificate chain not trusted: %w", err)
	}
	return leaf, nil
}

// certMatchesID reports whether a verified peer certificate matches the IKE
// identity the peer claimed in IDi/IDr, so a trusted certificate cannot be
// used to impersonate a different identity. An empty/zero id skips the check.
func certMatchesID(cert *x509.Certificate, id payload.IDPayload) error {
	switch id.Type {
	case payload.IDFQDN:
		want := string(id.Data)
		if slices.Contains(cert.DNSNames, want) {
			return nil
		}
		return fmt.Errorf("ike: certificate has no DNS SAN matching %q", want)
	case payload.IDRFC822:
		want := string(id.Data)
		if slices.Contains(cert.EmailAddresses, want) {
			return nil
		}
		return fmt.Errorf("ike: certificate has no email SAN matching %q", want)
	case payload.IDIPv4Addr, payload.IDIPv6Addr:
		want := net.IP(id.Data)
		for _, ip := range cert.IPAddresses {
			if ip.Equal(want) {
				return nil
			}
		}
		return fmt.Errorf("ike: certificate has no IP SAN matching %s", want)
	case payload.IDDERASN1DN:
		if bytes.Equal(cert.RawSubject, id.Data) {
			return nil
		}
		return fmt.Errorf("ike: certificate subject does not match the DER-DN identity")
	default:
		// No identity constraint we can check; trust rests on the chain alone.
		return nil
	}
}
