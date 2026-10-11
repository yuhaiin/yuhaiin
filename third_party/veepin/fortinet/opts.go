package fortinet

// Client option metadata for the Dial surface.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("fortinet", []client.OptSpec{
		{Key: OptServer, Kind: client.OptStr, Required: true, Help: "Fortinet SSL VPN server host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "443", Help: "server HTTPS port (default 443)"},
		{Key: OptUser, Kind: client.OptStr, Required: true, Help: "username"},
		{Key: OptPassword, Flag: "pass", Kind: client.OptStr, Secret: true, Help: "password"},
		{Key: OptRealm, Kind: client.OptStr, Help: "FortiOS realm"},
		{Key: OptCA, Kind: client.OptFilePath, Help: "PEM bundle to verify the server against"},
		{Key: OptInsecure, Kind: client.OptBool, Help: "skip TLS certificate verification (self-signed servers)"},
		{Key: OptNoDTLS, Kind: client.OptBool, Help: "stay on the TLS tunnel even where the gateway offers DTLS"},
		{Key: OptToken, Kind: client.OptStr, Secret: true, Help: "one-time code to answer a 2FA challenge (single use)"},
		{Key: OptTOTP, Kind: client.OptStr, Secret: true, Help: "base32 TOTP secret, to generate codes as the gateway asks"},
		client.TUNOpt(OptTUN),
	})
}
