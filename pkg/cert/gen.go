package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

type Ca struct {
	Cert       *x509.Certificate
	PrivateKey crypto.Signer
}

func ParseCa(certBytes, privateKeyBytes []byte) (*Ca, error) {
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		return nil, errors.New("decode cert failed")
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert failed: %w", err)
	}

	pemBlock, _ = pem.Decode(privateKeyBytes)
	if pemBlock == nil {
		return nil, errors.New("decode private key failed")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key failed: %w", err)
	}

	pk, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca public key is not ecdsa")
	}

	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("certificate is not a signing CA")
	}
	public, err := x509.MarshalPKIXPublicKey(pk.Public())
	if err != nil {
		return nil, err
	}
	expected, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(public, expected) {
		return nil, errors.New("CA certificate and private key do not match")
	}
	return &Ca{
		Cert:       cert,
		PrivateKey: pk,
	}, nil
}

// CertBytes pem
func (c *Ca) CertBytes() ([]byte, error) {
	if len(c.Cert.Raw) != 0 {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw}), nil
	}
	der, err := x509.CreateCertificate(rand.Reader, c.Cert, c.Cert, c.PrivateKey.Public(), c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create ca cert failed: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// PrivateKeyBytes pem
func (c *Ca) PrivateKeyBytes() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key failed: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// PublicKeyBytes pem
func (c *Ca) PublicKeyBytes() ([]byte, error) {
	data, err := x509.MarshalPKIXPublicKey(c.PrivateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal public key failed: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data}), nil
}

type ServerCert struct {
	Ca         *Ca
	Cert       *x509.Certificate
	PrivateKey crypto.Signer
}

func (c *ServerCert) PrivateKeyBytes() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key failed: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func (s *ServerCert) CertBytes() ([]byte, error) {
	der, err := x509.CreateCertificate(rand.Reader, s.Cert, s.Ca.Cert, s.PrivateKey.Public(), s.Ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create server cert failed: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (s *ServerCert) TlsCert() (tls.Certificate, error) {
	data, err := x509.CreateCertificate(rand.Reader, s.Cert, s.Ca.Cert, s.PrivateKey.Public(), s.Ca.PrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create server cert failed: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{data},
		PrivateKey:  s.PrivateKey,
	}, nil
}

func (c *Ca) GenerateServerCert(hosts ...string) (*ServerCert, error) {
	return c.GenerateServerCertWithAlgorithm(c.Cert.PublicKeyAlgorithm, hosts...)
}

// GenerateServerCertWithAlgorithm selects the leaf key independently of the CA.
// This allows TLS peers with restricted signature schemes to use a persisted CA.
func (c *Ca) GenerateServerCertWithAlgorithm(algorithm x509.PublicKeyAlgorithm, hosts ...string) (*ServerCert, error) {
	algo := GetAlgorithmsByPublicKeyAlgorithm(algorithm)
	// check http://itdoc.hitachi.co.jp/manuals/3021/30213D1130/D110071.HTM
	// privateKeyType = "PRIVATE KEY"

	pk, err := algo.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key failed: %w", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := minTime(notBefore.Add(30*24*time.Hour), c.Cert.NotAfter)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server serial number: %s", err)
	}

	var commonName string
	if len(hosts) > 0 {
		commonName = hosts[0]
	} else {
		commonName = rand.Text()
	}

	leafTemplate := x509.Certificate{
		Issuer:                c.Cert.Subject,
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName},
		PublicKeyAlgorithm:    algo.PublicKeyAlgorithm,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		PublicKey:             pk.Public(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if algorithm == x509.RSA {
		leafTemplate.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	_, err = rand.Read(leafTemplate.SubjectKeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server subject key id: %s", err)
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, ip)
		} else {
			leafTemplate.DNSNames = append(leafTemplate.DNSNames, h)
		}
	}

	leafTemplate.RawSubject, err = asn1.Marshal(leafTemplate.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ca subject: %s", err)
	}

	return &ServerCert{
		Ca:         c,
		Cert:       &leafTemplate,
		PrivateKey: pk,
	}, nil
}

type Algorithm struct {
	GenerateKey        func() (crypto.Signer, error)
	SignatureAlgorithm x509.SignatureAlgorithm
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
}

var algorithms = []Algorithm{
	{
		SignatureAlgorithm: x509.PureEd25519,
		PublicKeyAlgorithm: x509.Ed25519,
		GenerateKey: func() (crypto.Signer, error) {
			_, pk, err := ed25519.GenerateKey(rand.Reader)
			return pk, err
		},
	},
	{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		GenerateKey: func() (crypto.Signer, error) {
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		},
	},
	{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		GenerateKey: func() (crypto.Signer, error) {
			return rsa.GenerateKey(rand.Reader, 2048)
		},
	},
}

func GetAlgorithmsByPublicKeyAlgorithm(algo x509.PublicKeyAlgorithm) Algorithm {
	switch algo {
	case x509.RSA:
		return algorithms[2]
	case x509.ECDSA:
		return algorithms[1]
	case x509.Ed25519:
		return algorithms[0]
	default:
		return algorithms[0]
	}
}

// GenerateCa creates a named local authority. It never impersonates a public CA.
func GenerateCa() (*Ca, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	subject := pkix.Name{CommonName: "Yuhaiin Local CA", Organization: []string{"Yuhaiin"}}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: subject, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Ca{Cert: parsed, PrivateKey: key}, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
