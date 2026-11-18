package ike

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/ikev2/payload"
)

type testPKI struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &testPKI{ca: ca, caKey: key, roots: roots}
}

func (p *testPKI) leaf(t *testing.T, dns []string, ips []net.IP) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dns,
		IPAddresses:  ips,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}

func TestExpectedServerIdentity(t *testing.T) {
	explicit := FQDNIdentity("gw.example.com")
	tests := []struct {
		name    string
		remote  *Identity
		host    string
		want    Identity
		wantErr bool
	}{
		{name: "explicit wins", remote: &explicit, host: "192.0.2.1", want: explicit},
		{name: "hostname", host: "vpn.example.com", want: FQDNIdentity("vpn.example.com")},
		{name: "trailing dot", host: "vpn.example.com.", want: FQDNIdentity("vpn.example.com")},
		{name: "ipv4", host: "192.0.2.1", want: IPIdentity(net.ParseIP("192.0.2.1"))},
		{name: "bracketed ipv6 with zone", host: "[fe80::1%eth0]", want: IPIdentity(net.ParseIP("fe80::1"))},
		{name: "empty host", host: "", wantErr: true},
		{name: "empty explicit", remote: &Identity{Type: payload.IDFQDN}, host: "vpn.example.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expectedServerIdentity(tt.remote, tt.host)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Type != tt.want.Type || string(got.Data) != string(tt.want.Data) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCertMatchesExpectedID(t *testing.T) {
	pki := newTestPKI(t)
	cert, _ := pki.leaf(t, []string{"vpn.example.com", "*.wild.example.com"}, []net.IP{net.ParseIP("192.0.2.1")})

	ok := []Identity{
		FQDNIdentity("vpn.example.com"),
		FQDNIdentity("VPN.Example.COM"),
		FQDNIdentity("a.wild.example.com"),
		IPIdentity(net.ParseIP("192.0.2.1")),
	}
	for _, id := range ok {
		if err := certMatchesExpectedID(cert, id); err != nil {
			t.Errorf("%q: unexpected error %v", id.Data, err)
		}
	}
	bad := []Identity{
		FQDNIdentity("other.example.com"),
		IPIdentity(net.ParseIP("192.0.2.2")),
		{Type: payload.IDKeyID, Data: []byte("vpn.example.com")},
	}
	for _, id := range bad {
		if err := certMatchesExpectedID(cert, id); err == nil {
			t.Errorf("type %d %q: expected error", id.Type, id.Data)
		}
	}
}

// A responder holding any certificate from a trusted CA used to authenticate
// as long as the IDr it sent matched that certificate, even when the client was
// connecting to a different server and no server ID was configured.
func TestVerifyServerCertAuthBindsToServerHost(t *testing.T) {
	pki := newTestPKI(t)
	_, attackerDER := pki.leaf(t, []string{"attacker.example"}, []net.IP{net.ParseIP("198.51.100.7")})

	for _, tc := range []struct {
		name string
		host string
		idr  payload.IDPayload
	}{
		{name: "hostname", host: "vpn.example.com",
			idr: payload.IDPayload{Type: payload.IDFQDN, Data: []byte("attacker.example")}},
		{name: "ip", host: "192.0.2.1",
			idr: payload.IDPayload{Type: payload.IDIPv4Addr, Data: net.ParseIP("198.51.100.7").To4()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The attacker's certificate chains to the trusted root and
			// matches the IDr it claims: the pre-fix checks both pass.
			leaf, err := verifyPeerCertChain(attackerDER, nil, pki.roots)
			if err != nil {
				t.Fatal(err)
			}
			if err := certMatchesID(leaf, tc.idr); err != nil {
				t.Fatal(err)
			}

			c := &Client{cfg: ClientConfig{ServerHost: tc.host}, caRoots: pki.roots}
			inners := []payload.RawPayload{
				{Type: payload.TypeIDr, Body: payload.MarshalID(tc.idr)},
				{Type: payload.TypeCERT, Body: payload.MarshalCert(payload.CertPayload{
					Encoding: payload.CertX509Signature, Data: attackerDER})},
				{Type: payload.TypeAUTH, Body: payload.MarshalAuth(payload.AuthPayload{
					Method: payload.AuthDigitalSig, Data: []byte{0}})},
			}
			err = c.verifyServerCertAuth(inners)
			if !errors.Is(err, ErrAuthFailed) {
				t.Fatalf("verifyServerCertAuth() = %v, want ErrAuthFailed", err)
			}
			if !strings.Contains(err.Error(), "server certificate") {
				t.Fatalf("rejected for the wrong reason: %v", err)
			}
		})
	}
}
