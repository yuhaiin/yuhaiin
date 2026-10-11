package sstp

// Client option metadata for the Dial surface.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("sstp", []client.OptSpec{
		{Key: OptServer, Kind: client.OptStr, Required: true, Help: "SSTP server host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "443", Help: "server TCP port (default 443)"},
		{Key: OptUser, Kind: client.OptStr, Required: true, Help: "MS-CHAPv2 username"},
		{Key: OptPassword, Flag: "pass", Kind: client.OptStr, Secret: true, Required: true, Help: "MS-CHAPv2 password"},
		{Key: OptInsecure, Kind: client.OptBool, Help: "skip TLS certificate verification (self-signed servers)"},
		client.TUNOpt(OptTUNName),
	})
}
