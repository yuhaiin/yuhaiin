package main

import (
	"crypto/x509"
	"net"
	"testing"
)

func TestRecoveryCertificateHealthNameHandlesWildcardAndIP(t *testing.T) {
	for _, fixture := range []struct {
		certificate x509.Certificate
		want        string
	}{
		{x509.Certificate{DNSNames: []string{"*.example.test"}}, "recovery-health.example.test"},
		{x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, "127.0.0.1"},
		{x509.Certificate{}, ""},
	} {
		if got := recoveryCertificateName(&fixture.certificate); got != fixture.want {
			t.Errorf("health SAN = %q, want %q", got, fixture.want)
		}
	}
}
