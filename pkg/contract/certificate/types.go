// Package certificate describes managed HTTPS site certificates. It does not
// contain MITM or TLS Auto CA signers, account keys or DNS API credentials.
package certificate

import "time"

const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type Challenge struct {
	Type          string `json:"type"`
	DNSProviderID string `json:"dnsProviderId,omitempty"`
	HTTPGatewayID string `json:"httpGatewayId,omitempty"`
}

type Config struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Domains       []string  `json:"domains"`
	DirectoryURL  string    `json:"directoryUrl"`
	Email         string    `json:"email"`
	TermsAccepted bool      `json:"termsAccepted"`
	Challenge     Challenge `json:"challenge"`
	AutoRenew     bool      `json:"autoRenew"`
	// TrustPEM optionally trusts a private ACME CA. It contains public roots only
	// and never affects DNS provider or other application HTTP clients.
	TrustPEM string `json:"trustPem,omitempty"`
}

type Status struct {
	State       string             `json:"state"`
	Issuer      string             `json:"issuer,omitempty"`
	Serial      string             `json:"serial,omitempty"`
	NotBefore   time.Time          `json:"notBefore,omitzero"`
	NotAfter    time.Time          `json:"notAfter,omitzero"`
	NextAttempt time.Time          `json:"nextAttempt,omitzero"`
	LastAttempt time.Time          `json:"lastAttempt,omitzero"`
	LastSuccess time.Time          `json:"lastSuccess,omitzero"`
	FailureCode string             `json:"failureCode,omitempty"`
	Failures    int                `json:"failures,omitzero"`
	RenewalInfo *RenewalInfoStatus `json:"renewalInfo,omitzero"`
}

// RenewalInfoStatus contains only public CA scheduling information. Its failure
// count is independent of issuance failures and cannot reset their backoff.
type RenewalInfoStatus struct {
	State          string    `json:"state"`
	CheckedAt      time.Time `json:"checkedAt,omitzero"`
	NextCheck      time.Time `json:"nextCheck,omitzero"`
	WindowStart    time.Time `json:"windowStart,omitzero"`
	WindowEnd      time.Time `json:"windowEnd,omitzero"`
	ExplanationURL string    `json:"explanationUrl,omitempty"`
	Failures       int       `json:"failures,omitzero"`
}

type Reference struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Resource struct {
	Config     Config      `json:"config"`
	Revision   uint64      `json:"revision"`
	Status     Status      `json:"status"`
	References []Reference `json:"references"`
}

// DNSProvider is the public projection; tokens are write-only inputs elsewhere.
type DNSProvider struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	ZoneID        string `json:"zoneId"`
	ZoneName      string `json:"zoneName"`
	Revision      uint64 `json:"revision"`
	HasCredential bool   `json:"hasCredential"`
}
