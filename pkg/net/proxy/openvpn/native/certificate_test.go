package native

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestTLSSystemTrustRequiresGatewayIdentity(t *testing.T) {
	for _, gateway := range []string{"vpn.example:1194", "[2001:db8::1]:1194"} {
		t.Run(gateway, func(t *testing.T) {
			cfg, err := (Config{Gateway: gateway}).TLSConfig()
			if err != nil {
				t.Fatal(err)
			}
			host, _, err := net.SplitHostPort(gateway)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ServerName != host || cfg.InsecureSkipVerify || cfg.RootCAs == nil {
				t.Fatalf("system trust must verify gateway identity: %+v", cfg)
			}
		})
	}
	if _, err := (Config{}).TLSConfig(); err == nil {
		t.Fatal("system trust without a gateway identity must fail")
	}
}

func TestTLSCertificateVerification(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	otherCAPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER}))
	leaf := func(name string, usage x509.ExtKeyUsage, expired bool) tls.Certificate {
		t.Helper()
		cert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "OpenVPN server"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if name != "" {
			cert.DNSNames = []string{name}
		}
		if expired {
			cert.NotAfter = now.Add(-time.Minute)
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	cnOnly := leaf("", x509.ExtKeyUsageServerAuth, false)
	named := leaf("vpn.example", x509.ExtKeyUsageServerAuth, false)
	for _, test := range []struct {
		name, serverName string
		certificate      tls.Certificate
		untrusted, skip  bool
		wantSuccess      bool
	}{
		{name: "CA-only without SAN", certificate: cnOnly, wantSuccess: true},
		{name: "named server", serverName: "vpn.example", certificate: named, wantSuccess: true},
		{name: "untrusted CA without SAN", certificate: cnOnly, untrusted: true},
		{name: "untrusted named server", serverName: "vpn.example", certificate: named, untrusted: true},
		{name: "wrong server EKU", certificate: leaf("", x509.ExtKeyUsageClientAuth, false)},
		{name: "expired certificate", certificate: leaf("", x509.ExtKeyUsageServerAuth, true)},
		{name: "hostname mismatch", serverName: "other.example", certificate: named},
		{name: "missing SAN for named server", serverName: "vpn.example", certificate: cnOnly},
		{name: "explicit insecure opt-in", serverName: "other.example", certificate: named, untrusted: true, skip: true, wantSuccess: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := Config{CACertPEM: caPEM, ServerName: test.serverName, InsecureSkipVerify: test.skip}
			if test.untrusted {
				cfg.CACertPEM = otherCAPEM
			}
			clientConfig, err := cfg.TLSConfig()
			if err != nil {
				t.Fatal(err)
			}
			clientWire, serverWire := net.Pipe()
			defer clientWire.Close()
			defer serverWire.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			serverDone := make(chan error, 1)
			go func() {
				serverDone <- tls.Server(serverWire, &tls.Config{
					Certificates: []tls.Certificate{test.certificate}, MinVersion: tls.VersionTLS12,
					SessionTicketsDisabled: true,
				}).HandshakeContext(ctx)
			}()
			err = tls.Client(clientWire, clientConfig).HandshakeContext(ctx)
			_ = clientWire.Close()
			<-serverDone
			if (err == nil) != test.wantSuccess {
				t.Fatalf("handshake error = %v, want success %v", err, test.wantSuccess)
			}
		})
	}
}
