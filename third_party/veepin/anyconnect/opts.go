package anyconnect

// Client option metadata for the Dial surface.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("anyconnect", []client.OptSpec{
		{Key: OptServer, Kind: client.OptStr, Required: true, Help: "AnyConnect server host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "443", Help: "server HTTPS port (default 443)"},
		{Key: OptUser, Kind: client.OptStr, Required: true, Help: "username"},
		{Key: OptPassword, Flag: "pass", Kind: client.OptStr, Secret: true, Required: true, Help: "password"},
		{Key: OptInsecure, Kind: client.OptBool, Help: "skip TLS certificate verification (self-signed servers)"},
		{Key: OptNoDTLS, Kind: client.OptBool, Help: "keep the data channel on TLS instead of DTLS/UDP"},
		client.TUNOpt(OptTUNName),
	})
}
