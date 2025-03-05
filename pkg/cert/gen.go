package cert

import (
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
	mrand "math/rand/v2"
	"net"
	"time"
)

var IssuersTemplate = []pkix.Name{
	{
		Country:      []string{"BE"},
		Organization: []string{"GlobalSign nv-sa"},
		CommonName:   "GlobalSign ECC OV SSL CA 2018",
	},
	/*CN = GlobalSign Organization Validation CA - SHA256 - G3 O = GlobalSign nv-sa C = BE*/
	{
		Country:      []string{"BE"},
		Organization: []string{"GlobalSign nv-sa"},
		CommonName:   "GlobalSign Organization Validation CA - SHA256 - G3",
	},
	/* C=US, O=Let's Encrypt, CN=E6 */
	{
		Country:      []string{"US"},
		Organization: []string{"Let's Encrypt"},
		CommonName:   "E6",
	},
	{
		Country:      []string{"US"},
		Organization: []string{"Let's Encrypt"},
		CommonName:   "E5",
	},
	{
		Country:      []string{"US"},
		Organization: []string{"Let's Encrypt"},
		CommonName:   "R10",
	},

	/*CN = WR2 O = Google Trust Services C = US*/
	{
		Country:      []string{"US"},
		Organization: []string{"Google Trust Services"},
		CommonName:   "WR2",
	},

	/*CN = Microsoft Azure ECC TLS Issuing CA 07 O = Microsoft Corporation C = US*/
	{
		Country:      []string{"US"},
		Organization: []string{"Microsoft Corporation"},
		CommonName:   "Microsoft Azure ECC TLS Issuing CA 07",
	},

	/*CN = Amazon RSA 2048 M01 O = Amazon C = US*/
	{
		Country:      []string{"US"},
		Organization: []string{"Amazon"},
		CommonName:   "Amazon RSA 2048 M01",
	},

	/*CN = GeoTrust TLS RSA CA G1 OU = www.digicert.com O = DigiCert Inc C = US*/
	{
		Country:            []string{"US"},
		Organization:       []string{"DigiCert Inc"},
		OrganizationalUnit: []string{"www.digicert.com"},
		CommonName:         "GeoTrust TLS RSA CA G1",
	},
}

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

	return &Ca{
		Cert:       cert,
		PrivateKey: pk,
	}, nil
}

// CertBytes pem
func (c *Ca) CertBytes() ([]byte, error) {
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
	algo := GetAlgorithmsByPublicKeyAlgorithm(c.Cert.PublicKeyAlgorithm)
	// check http://itdoc.hitachi.co.jp/manuals/3021/30213D1130/D110071.HTM
	// privateKeyType = "PRIVATE KEY"

	pk, err := algo.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key failed: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

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
		PublicKeyAlgorithm:    c.Cert.PublicKeyAlgorithm,
		SignatureAlgorithm:    c.Cert.SignatureAlgorithm,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		PublicKey:             pk.Public(),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
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
	SignatureAlgorithm x509.SignatureAlgorithm
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	GenerateKey        func() (crypto.Signer, error)
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

func GenerateCa() (*Ca, error) {
	var err error
	notBefore := time.Now()
	notAfter := notBefore.Add(100 * 365 * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	var rootTemplate *x509.Certificate

	algo := algorithms[mrand.IntN(len(algorithms))]
	// check http://itdoc.hitachi.co.jp/manuals/3021/30213D1130/D110071.HTM
	// privateKeyType = "PRIVATE KEY"

	rootKey, err := algo.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key failed: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ca serial number: %s", err)
	}

	issue := IssuersTemplate[mrand.IntN(len(IssuersTemplate))]

	rootTemplate = &x509.Certificate{
		Issuer:                issue,
		SerialNumber:          serialNumber,
		Subject:               issue,
		Version:               3,
		PublicKeyAlgorithm:    algo.PublicKeyAlgorithm,
		SignatureAlgorithm:    algo.SignatureAlgorithm,
		PublicKey:             rootKey.Public(),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootTemplate.RawSubject, err = asn1.Marshal(rootTemplate.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ca subject: %s", err)
	}

	return &Ca{
		Cert:       rootTemplate,
		PrivateKey: rootKey,
	}, nil
}
