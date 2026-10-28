package certificate

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"uuid"
)

func ValidID(id string) bool {
	u, err := uuid.Parse(id)
	return err == nil && u != uuid.Nil() && u.String() == id
}

// Validate requires normalized ASCII DNS SANs. Names with international labels
// must be supplied as A-labels; no implicit rewriting changes CA authorizations.
func (c Config) Validate() error {
	if !ValidID(c.ID) || len(c.Name) == 0 || len(c.Name) > 128 {
		return errors.New("certificate requires a stable ID and a name of 1–128 bytes")
	}
	if len(c.Domains) == 0 || len(c.Domains) > 32 {
		return errors.New("certificate requires 1–32 DNS names")
	}
	seen := make(map[string]bool, len(c.Domains))
	for _, name := range c.Domains {
		if !ValidDomain(name, c.Challenge.Type == "dns-01") || seen[name] {
			return errors.New("invalid, duplicate or unsupported wildcard DNS name")
		}
		seen[name] = true
	}
	u, err := url.Parse(c.DirectoryURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" || len(c.DirectoryURL) > 2048 {
		return errors.New("ACME directory must be an HTTPS URL without credentials, query or fragment")
	}
	address, err := mail.ParseAddress(c.Email)
	if err != nil || address.Address != c.Email || len(c.Email) > 254 {
		return errors.New("ACME account requires an email address")
	}
	if !c.TermsAccepted {
		return errors.New("ACME terms must be explicitly accepted")
	}
	switch c.Challenge.Type {
	case "http-01":
		if !ValidID(c.Challenge.HTTPGatewayID) || c.Challenge.DNSProviderID != "" {
			return errors.New("HTTP-01 requires one explicitly enabled HTTP gateway")
		}
	case "dns-01":
		if !ValidID(c.Challenge.DNSProviderID) || c.Challenge.HTTPGatewayID != "" {
			return errors.New("DNS-01 requires one DNS provider")
		}
	default:
		return errors.New("unsupported ACME challenge type")
	}
	if len(c.TrustPEM) > 64<<10 {
		return errors.New("ACME trust roots exceed 64 KiB")
	}
	rest := []byte(c.TrustPEM)
	for len(strings.TrimSpace(string(rest))) != 0 {
		rest = bytes.TrimSpace(rest)
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("ACME trust accepts public CA PEM blocks only")
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("ACME trust accepts public CA certificates only")
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
			return errors.New("invalid ACME trust CA")
		}
		rest = next
	}
	return nil
}

func ValidDomain(name string, wildcard bool) bool {
	if wildcard {
		name = strings.TrimPrefix(name, "*.")
	}
	if name == "" || len(name) > 253 || strings.ToLower(name) != name || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}
