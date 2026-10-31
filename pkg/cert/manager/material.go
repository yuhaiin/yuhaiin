// Package manager manages site-certificate lifecycles above the existing TLS
// engines. It never uses or modifies Gateway MITM and TLS Auto CA signers.
package manager

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

// ValidateMaterial verifies the key pair, chain, purpose, exact requested SAN set
// and lifetime before publication. A CA signer cannot become a site certificate.
func ValidateMaterial(c contract.Config, m certificates.Material, now time.Time) (*tls.Certificate, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if len(m.CertificatePEM) == 0 || len(m.CertificatePEM) > 256<<10 {
		return nil, errors.New("invalid certificate chain size")
	}
	key := m.PrivateKey.Bytes()
	if len(key) == 0 || len(key) > 32<<10 {
		return nil, errors.New("invalid certificate key size")
	}
	pair, err := tls.X509KeyPair(m.CertificatePEM, key)
	clear(key)
	if err != nil {
		return nil, errors.New("invalid certificate key pair")
	}
	if len(pair.Certificate) == 0 || len(pair.Certificate) > 8 {
		return nil, errors.New("invalid certificate chain length")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid site certificate")
	}
	if leaf.IsCA || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.EmailAddresses) != 0 {
		return nil, errors.New("managed certificate must contain DNS site identities only")
	}
	want, got := slices.Clone(c.Domains), slices.Clone(leaf.DNSNames)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		return nil, errors.New("issued certificate SANs differ from requested DNS names")
	}
	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return nil, errors.New("RSA certificate key must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return nil, errors.New("EC certificate key must be at least 256 bits")
		}
	case ed25519.PublicKey:
	default:
		return nil, errors.New("unsupported certificate public key")
	}
	var roots *x509.CertPool
	if c.TrustPEM != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(c.TrustPEM)) {
			return nil, errors.New("invalid private ACME trust roots")
		}
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("invalid certificate intermediate")
		}
		intermediates.AddCert(intermediate)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, errors.New("site certificate chain, purpose or lifetime verification failed")
	}
	pair.Leaf = leaf
	return &pair, nil
}
