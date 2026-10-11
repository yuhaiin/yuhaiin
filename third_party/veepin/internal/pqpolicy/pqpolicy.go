// Package pqpolicy is the one place that decides what "post-quantum" means in
// this tree.
//
// Every pq- protocol variant forwards a single boolean here and this package
// decides the rest: which key exchange mechanisms are acceptable, which
// signature algorithms count as post-quantum authentication, and what a
// credential has to be before a server carrying that name is allowed to start.
// Ten facades therefore share one definition rather than ten, and when a future
// mechanism should join the accepted set it joins here and every variant moves
// together.
//
// The contract, stated once, is:
//
//	Under a pq- name both halves of the handshake are post-quantum -- key
//	exchange AND authentication -- and anything less is refused rather than
//	negotiated down.
//
// "Refused" is load-bearing. A pq- server meeting a classical client produces a
// handshake failure with a log line naming what was missing; it does not quietly
// fall back. This is the same argument doc/security.md makes for aborting on a
// refused mlockall rather than warning and continuing: a protection that
// silently does nothing is worse than no protection, because the appearance
// invites confidence the process has not earned.
//
// One protocol cannot meet the contract and ships anyway, by name and with the
// reason recorded: see [SSHKeyExchangeOnly].
package pqpolicy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"

	"github.com/xen0bit/veepin/internal/vlog"
)

// OptKey is the option-map key a variant injects to put the base facade into
// post-quantum-only mode.
//
// It is deliberately NOT an exported Opt* const on any facade and deliberately
// NOT in any OptSpec table, because it is not an option an operator sets: it is
// how the registry name reaches the parse function. TestEveryOptConstIsDescribedByAnOptSpec
// polices the former and the flag generator reads the latter, so keeping it out
// of both is what stops `-post-quantum-only` appearing as a flag on the base
// protocol -- which would reintroduce exactly the forgettable modifier the
// variant scheme exists to replace.
const OptKey = "post-quantum-only"

// Errors this package reports. They are sentinels so a caller -- a test, a
// facade, the supervisor -- can distinguish "the operator asked for something
// impossible" from "the peer would not comply".
var (
	// ErrClassicalCredential is reported when a pq- server is pointed at a
	// certificate that is not ML-DSA. It surfaces at construction time, before
	// the TUN is opened and before anything binds.
	ErrClassicalCredential = errors.New("pqpolicy: credential is not post-quantum")

	// ErrClassicalPeer is reported when a peer presented a certificate that is
	// not ML-DSA on a connection carrying the pq- contract.
	ErrClassicalPeer = errors.New("pqpolicy: peer certificate is not post-quantum")
)

// Requested reports whether an options map carries the post-quantum-only
// marker. Base facades call this in their parse functions; it is the whole of
// what a base protocol needs to know about variants.
func Requested(opts map[string]string) bool { return opts[OptKey] == "true" }

// Force returns a copy of opts with the post-quantum marker set, plus any extra
// options the variant pins, refusing a caller who explicitly asked for
// something different.
//
// The refusal is the point. A variant that silently overrode an operator's
// explicit `-no-dtls=false` would leave them believing the UDP data channel was
// bound when it was not -- the operator-facing half of the same "silently does
// nothing" failure the package comment describes. Setting an option to the value
// the variant was going to force anyway is accepted, because that is agreement
// rather than conflict.
func Force(variant string, opts, extra map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(opts)+len(extra)+1)
	maps.Copy(out, opts)

	for _, key := range sortedKeys(extra) {
		want := extra[key]
		if got, set := out[key]; set && got != want {
			return nil, fmt.Errorf("%s: %s=%q is not available here: this variant always sets %s=%q",
				variant, key, got, key, want)
		}
		out[key] = want
	}
	out[OptKey] = "true"
	return out, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Curves is the set of key exchange mechanisms that satisfy the contract: every
// mechanism crypto/tls offers whose shared secret has a post-quantum component.
//
// It returns a fresh slice each call. Handing out the package's own backing
// array would let one facade's later append reach every other facade's config,
// which is the kind of aliasing bug that shows up as an unrelated protocol
// quietly accepting a classical curve.
//
// Note that ORDER IS IRRELEVANT here: crypto/tls documents that
// Config.CurvePreferences is treated as a set and the selection uses its own
// internal preference order. This list is therefore a floor, not a ranking.
func Curves() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519MLKEM768,     // 4588 -- the default's leader, and what every PQ peer speaks
		tls.SecP256r1MLKEM768,  // 4587
		tls.SecP384r1MLKEM1024, // 4589
		tls.MLKEM1024,          // 514 -- pure ML-KEM, no classical half
	}
}

// SignatureSchemes is the set of TLS 1.3 signature schemes that satisfy the
// authentication half of the contract.
func SignatureSchemes() []tls.SignatureScheme {
	return []tls.SignatureScheme{tls.MLDSA44, tls.MLDSA65, tls.MLDSA87}
}

// HardenTLS raises cfg to the contract, in place.
//
// Three things happen, and each one is a refusal rather than a preference:
//
//   - The version floor goes to TLS 1.3. Only TLS 1.3 carries a key_share, so
//     nothing below it can carry a post-quantum key exchange at all. A peer
//     capped at 1.2 is refused with "protocol version not supported".
//   - CurvePreferences is pinned to [Curves]. Any peer offering only classical
//     mechanisms is refused with "no key exchanges supported by both client and
//     server". This is the ONE place in the tree permitted to set this field;
//     see TestNoTLSConfigPinsCurvePreferences.
//   - VerifyPeerCertificate is chained with [RequireMLDSALeaf], so a peer that
//     presents a classical certificate is refused after the chain verifies.
//
// The existing VerifyPeerCertificate, if any, is preserved and runs first: this
// tightens a config, and a policy that discarded a facade's own verification
// while claiming to strengthen it would be worse than not being applied.
func HardenTLS(cfg *tls.Config) {
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	// MaxVersion is left alone deliberately. Several facades cap it at 1.3
	// already and a future 1.4 that keeps key_share should not be excluded by a
	// cap written here, years earlier, for a reason that will have expired.
	cfg.CurvePreferences = Curves()

	prev := cfg.VerifyPeerCertificate
	cfg.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
		if prev != nil {
			if err := prev(raw, chains); err != nil {
				return err
			}
		}
		return RequireMLDSALeaf(raw, chains)
	}
}

// RequireMLDSALeaf is the VerifyPeerCertificate hook enforcing the
// authentication half against whatever the peer presented.
//
// An empty chain is accepted, and that is correct for both roles rather than a
// hole. A client always receives the server's certificate, so this enforces
// there unconditionally. A server receives one only when it asked for it, and a
// server that asked for none is authenticating its users by password inside the
// tunnel -- which travels inside the post-quantum channel and is not a
// quantum-broken primitive. See doc/security.md.
func RequireMLDSALeaf(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("pqpolicy: parsing the peer's leaf certificate: %w", err)
	}
	if leaf.PublicKeyAlgorithm != x509.MLDSA {
		return fmt.Errorf("%w: %s presented a %s key, want ML-DSA",
			ErrClassicalPeer, leaf.Subject.CommonName, leaf.PublicKeyAlgorithm)
	}
	return nil
}

// CheckCredential rejects a server credential that cannot carry post-quantum
// authentication.
//
// Calling this at construction time is what makes the guarantee mean something
// operationally. Left to the first handshake, an operator who pointed a pq-
// server at their existing RSA certificate would see a listener come up
// normally and then refuse every client, with the cause three layers down in a
// TLS error. Failing in NewServer -- before the TUN is opened, before anything
// binds -- names the problem while the operator is still looking at it.
func CheckCredential(cert tls.Certificate) error {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return fmt.Errorf("%w: the credential carries no certificate", ErrClassicalCredential)
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("pqpolicy: parsing the server certificate: %w", err)
		}
		leaf = parsed
	}
	if leaf.PublicKeyAlgorithm != x509.MLDSA {
		return fmt.Errorf("%w: the certificate holds a %s key, want ML-DSA (FIPS 204). "+
			"A listener created under a pq- name through the management panel generates "+
			"one automatically; otherwise mint an ML-DSA certificate, or drop the pq- "+
			"prefix to use the base protocol",
			ErrClassicalCredential, leaf.PublicKeyAlgorithm)
	}
	return nil
}

// CheckCredentialPEM is the same check against a PEM pair, for facades that
// hold their credentials as bytes rather than as a parsed tls.Certificate.
func CheckCredentialPEM(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("pqpolicy: loading the server credential: %w", err)
	}
	return CheckCredential(pair)
}

// SSHKeyExchangeOnly is the single exception to the contract, recorded here by
// name so that it is a decision rather than an inconsistency.
//
// SSH has a post-quantum key exchange and NO post-quantum signature algorithm
// -- not in OpenSSH, not in golang.org/x/crypto, not in a finished
// specification. OpenSSH says so itself at https://www.openssh.org/pq.html:
// signature support is future work, and its stated reason is that
// store-now-decrypt-later does not apply to signatures the way it applies to
// key agreement.
//
// So pq-ssh forces mlkem768x25519-sha256 and constrains nothing about host keys
// or user keys. It ships anyway because the alternative is worse: without it
// veepin's SSH silently settles for curve25519-sha256 against any peer older
// than OpenSSH 9.9, which is most of them.
//
// TestSSHIsTheOnlyPQAuthException holds this list at one entry.
var SSHKeyExchangeOnly = map[string]string{
	"pq-ssh": "SSH has no post-quantum signature algorithm in any specification " +
		"or implementation; see https://www.openssh.org/pq.html",
}

// KeyExchangeOnly reports whether a variant is excused the authentication half,
// and why. The reason is returned so a caller logging the exemption states the
// cause rather than the mere fact.
func KeyExchangeOnly(variant string) (string, bool) {
	reason, ok := SSHKeyExchangeOnly[variant]
	return reason, ok
}

// SSHKeyExchanges is the key exchange list a pq- SSH connection pins.
//
// golang.org/x/crypto/ssh implements exactly one post-quantum key exchange, and
// OpenSSH gained the same name in 9.9 and made it the default in 10.0. Note
// what is NOT here: sntrup761x25519-sha512@openssh.com, OpenSSH's PQ kex from
// 9.0 through 9.8, which x/crypto does not implement at all. A peer in that
// range therefore has no post-quantum mechanism in common with veepin and is
// refused -- correctly, and visibly, where today it silently settles on
// curve25519-sha256.
func SSHKeyExchanges() []string { return []string{"mlkem768x25519-sha256"} }

// Describe renders the contract for a log line at startup, so an operator can
// see in the server's own output which guarantee is in force.
func Describe(variant string) string {
	var b strings.Builder
	b.WriteString(variant)
	b.WriteString(": post-quantum enforced — key exchange ")
	if reason, only := KeyExchangeOnly(variant); only {
		b.WriteString("only (authentication is classical: ")
		b.WriteString(reason)
		b.WriteString(")")
		return b.String()
	}
	b.WriteString("and authentication; classical peers are refused")
	return b.String()
}

// Announce writes the contract to the process log, so an operator starting a
// pq- listener or dialling a pq- name sees which guarantee is in force in the
// server's own output.
//
// Describe existed from the first commit of this package with that promise in
// its doc comment, and nothing called it. The gap was not cosmetic in two ways.
// An operator had no way to tell a `pq-` process from its base at runtime; and
// the veepin<->veepin interop cells had no line to assert on, which matters more
// than it sounds. Both ends of a self cell harden, so if the hardening silently
// stopped applying, BOTH would drop to a classical handshake, agree with each
// other perfectly, and the cell's ping would pass -- the mutually-consistent
// failure class AGENTS.md names, and exactly what runInteropRequiringLog exists
// to catch.
//
// It goes to stdout at Info rather than through a facade's Logger because it is
// a statement about the process's configuration, made before any facade is
// constructed and while the option map is still the only thing that exists.
// ikev2's -pq deprecation notice is written the same way, for the same reason.
func Announce(variant string) {
	vlog.Text(os.Stdout).Printf("%s", Describe(variant))
}
