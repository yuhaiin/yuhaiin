package nebula

// Trust anchors.
//
// A nebula host trusts a set of CA certificates and nothing else. Every peer it
// will speak to must present a certificate signed by one of them, and the
// address that peer is allowed to use is the one written into that certificate.
// There is no separate authorization step: verifying the certificate *is* the
// authorization, which is why the checks here are the whole security boundary
// between the mesh and anyone who can send it a datagram.

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"
)

// CAPool is the set of certificate authorities a host trusts.
type CAPool struct {
	byFingerprint map[string]*Certificate
}

// NewCAPool returns an empty pool.
func NewCAPool() *CAPool {
	return &CAPool{byFingerprint: map[string]*Certificate{}}
}

// NewCAPoolFromPEM builds a pool from a PEM bundle, which may hold several CAs
// so that a mesh can be migrated from one root to another without downtime.
func NewCAPoolFromPEM(b []byte) (*CAPool, error) {
	pool := NewCAPool()
	for len(b) > 0 {
		c, rest, err := UnmarshalCertificatePEM(b)
		if err != nil {
			return nil, err
		}
		if err := pool.Add(c); err != nil {
			return nil, err
		}
		b = rest
	}
	if len(pool.byFingerprint) == 0 {
		return nil, fmt.Errorf("nebula: CA bundle contains no certificates")
	}
	return pool, nil
}

// Add installs a CA certificate as a trust anchor.
func (p *CAPool) Add(c *Certificate) error {
	if !c.IsCA {
		return fmt.Errorf("nebula: %q is not a CA certificate", c.Name)
	}
	if c.Curve != Curve25519 {
		return fmt.Errorf("nebula: CA %q uses %v: %w", c.Name, c.Curve, ErrUnsupportedCurve)
	}
	// A CA is self-signed, so it authenticates itself. Rejecting one that fails
	// this check keeps a corrupted bundle from being trusted as an anchor.
	if !c.CheckSignature(c.PublicKey) {
		return fmt.Errorf("nebula: CA %q is not correctly self-signed: %w", c.Name, ErrSignature)
	}
	p.byFingerprint[c.Fingerprint()] = c
	return nil
}

// CAs returns the trusted anchors, keyed by fingerprint.
func (p *CAPool) CAs() map[string]*Certificate { return p.byFingerprint }

// Verify checks a peer certificate against the pool at time t, returning the CA
// that signed it.
func (p *CAPool) Verify(c *Certificate, t time.Time) (*Certificate, error) {
	if c.Curve != Curve25519 {
		return nil, fmt.Errorf("nebula: peer certificate uses %v: %w", c.Curve, ErrUnsupportedCurve)
	}
	if c.IsCA {
		// A CA certificate is a trust anchor, never a host identity. Accepting
		// one here would let anyone holding the CA key impersonate every host.
		return nil, fmt.Errorf("nebula: peer presented a CA certificate as a host identity")
	}
	if c.Expired(t) {
		return nil, fmt.Errorf("nebula: certificate %q valid %v..%v: %w",
			c.Name, c.NotBefore.UTC(), c.NotAfter.UTC(), ErrExpired)
	}

	ca, ok := p.byFingerprint[hex.EncodeToString(c.Issuer)]
	if !ok {
		return nil, fmt.Errorf("nebula: certificate %q names issuer %x: %w",
			c.Name, c.Issuer, ErrUnknownIssuer)
	}
	if ca.Expired(t) {
		return nil, fmt.Errorf("nebula: CA %q has expired: %w", ca.Name, ErrExpired)
	}
	if !c.CheckSignature(ca.PublicKey) {
		return nil, fmt.Errorf("nebula: certificate %q: %w", c.Name, ErrSignature)
	}
	if err := checkConstraints(ca, c); err != nil {
		return nil, err
	}
	return ca, nil
}

// checkConstraints enforces the limits a CA may place on what it will vouch
// for. A CA that names networks or groups may only sign certificates within
// them, which is how a mesh delegates signing authority to a subordinate
// without handing over the whole address space.
//
// An unconstrained CA — no networks, no groups — vouches for anything, which is
// the default `nebula-cert ca` produces.
func checkConstraints(ca, c *Certificate) error {
	if len(ca.Networks) > 0 {
		for _, n := range c.Networks {
			if !withinAny(ca.Networks, n) {
				return fmt.Errorf("nebula: certificate %q claims %v, outside the range CA %q may sign",
					c.Name, n, ca.Name)
			}
		}
	}
	if len(ca.UnsafeNetworks) > 0 {
		for _, n := range c.UnsafeNetworks {
			if !withinAny(ca.UnsafeNetworks, n) {
				return fmt.Errorf("nebula: certificate %q claims unsafe network %v, outside the range CA %q may sign",
					c.Name, n, ca.Name)
			}
		}
	}
	if len(ca.Groups) > 0 {
		allowed := make(map[string]struct{}, len(ca.Groups))
		for _, g := range ca.Groups {
			allowed[g] = struct{}{}
		}
		for _, g := range c.Groups {
			if _, ok := allowed[g]; !ok {
				return fmt.Errorf("nebula: certificate %q claims group %q, which CA %q may not sign",
					c.Name, g, ca.Name)
			}
		}
	}
	return nil
}

// withinAny reports whether p is contained in one of the outer prefixes.
func withinAny(outer []netip.Prefix, p netip.Prefix) bool {
	for _, o := range outer {
		if o.Bits() <= p.Bits() && o.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
