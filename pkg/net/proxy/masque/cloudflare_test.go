package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func testMASQUECertificate(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPrepareTLSConfigPeerPinning(t *testing.T) {
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := PrepareTlsConfig(clientKey, &trusted.PublicKey, [][]byte{testMASQUECertificate(t, clientKey)}, ConnectSNI2)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate == nil {
		t.Fatal("custom peer pinning must be installed when skipping chain verification")
	}

	trustedCert := testMASQUECertificate(t, trusted)
	otherCert := testMASQUECertificate(t, other)
	for _, tc := range []struct {
		name    string
		certs   [][]byte
		wantErr bool
	}{
		{"no peer cert", nil, true},
		{"matching leaf", [][]byte{trustedCert}, false},
		{"matching leaf with unrelated intermediate", [][]byte{trustedCert, otherCert}, false},
		{"untrusted leaf", [][]byte{otherCert}, true},
		{"untrusted leaf with trusted intermediate", [][]byte{otherCert, trustedCert}, true},
		{"invalid leaf", [][]byte{[]byte("invalid")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := cfg.VerifyPeerCertificate(tc.certs, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("VerifyPeerCertificate() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestPrepareTLSConfigRefreshesClientCertificate(t *testing.T) {
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := PrepareTlsConfig(clientKey, &clientKey.PublicKey, [][]byte{testMASQUECertificate(t, clientKey)}, ConnectSNI2)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GetClientCertificate == nil {
		t.Fatal("client certificate must be generated for every handshake")
	}
	for range 2 {
		cert, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
		if err != nil {
			t.Fatal(err)
		}
		if len(cert.Certificate) == 0 {
			t.Fatal("empty client certificate chain")
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if time.Until(leaf.NotAfter) < 23*time.Hour {
			t.Fatalf("certificate expires too soon: %v", leaf.NotAfter)
		}
	}
}
