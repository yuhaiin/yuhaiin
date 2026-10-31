package certificate

import (
	"testing"
	"uuid"
)

func TestConfigValidation(t *testing.T) {
	c := Config{ID: uuid.New().String(), Name: "site", Domains: []string{"site.example"}, DirectoryURL: LetsEncryptStaging, Email: "ops@example.com", TermsAccepted: true, Challenge: Challenge{Type: "http-01", HTTPGatewayID: uuid.New().String()}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.DirectoryURL = "http://example.com/directory" },
		func(c *Config) { c.DirectoryURL = "https://token@example.com/directory" },
		func(c *Config) { c.DirectoryURL = "https://example.com/directory?token=secret" },
		func(c *Config) { c.Domains = []string{"*.example.com"} },
		func(c *Config) { c.Domains = []string{"site.example", "site.example"} },
		func(c *Config) { c.Domains = []string{"127.0.0.1"} },
		func(c *Config) { c.Domains = []string{"SITE.example"} },
		func(c *Config) { c.TrustPEM = "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----" },
		func(c *Config) { c.TermsAccepted = false },
		func(c *Config) { c.Challenge.DNSProviderID = uuid.New().String() },
	} {
		invalid := c
		mutate(&invalid)
		if err := invalid.Validate(); err == nil {
			t.Fatalf("invalid config accepted: %+v", invalid)
		}
	}
	c.Challenge = Challenge{Type: "dns-01", DNSProviderID: uuid.New().String()}
	c.Domains = []string{"*.example.com", "example.com"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
