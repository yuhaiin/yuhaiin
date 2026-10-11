package ikev2

// Client option metadata: the panel and `veepin profile` render ikev2's Dial
// surface from this, so every key must stay in step with what parseOptions
// reads (cmd/veepin's TestClientOptSpecsMatchTheKeysTheProtocolReads enforces
// exactly that). Required and Secret mirror the NetworkManager plugin's
// requireKeys/secretMissing for the same protocol.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("ikev2", []client.OptSpec{
		{Key: OptGateway, Flag: "server", Kind: client.OptStr, Required: true, Help: "VPN server host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "500", Help: "server IKE port (default 500) — with -tcp this is the TCP port instead, 4500 unless set"},
		{Key: OptPSK, Kind: client.OptStr, Secret: true, Help: "pre-shared key"},
		{Key: OptLocalID, Flag: "id", Kind: client.OptStr, Required: true, Help: "local identity presented to the server"},
		{Key: OptServerID, Kind: client.OptStr, Help: "expected server identity (verified if set)"},
		{Key: OptUser, Kind: client.OptStr, Help: "EAP-MSCHAPv2 username (enables EAP instead of client PSK)"},
		{Key: OptPassword, Flag: "pass", Kind: client.OptStr, Secret: true, Help: "EAP-MSCHAPv2 password"},
		{Key: OptCert, Kind: client.OptFilePath, Help: "client certificate PEM (enables certificate auth instead of PSK)"},
		{Key: OptKey, Kind: client.OptFilePath, Secret: true, Help: "client private-key PEM (with cert)"},
		{Key: OptCA, Kind: client.OptFilePath, Help: "CA bundle PEM to verify the server (default system roots)"},
		{Key: OptRekey, Kind: client.OptInt, Default: "3600", Help: "Child SA rekey interval in seconds (0 = default 3600)"},
		{Key: OptIKERekey, Kind: client.OptInt, Default: "14400", Help: "IKE SA rekey interval in seconds (0 = default 14400)"},
		client.ShapeOpt(OptShape, "upstream"),
		// DEPRECATED, and kept for one release. `veepin connect pq-ikev2` is
		// the replacement and is strictly stronger: -pq OFFERS ML-KEM and
		// accepts a classical SA when the responder declines, which is a
		// preference rather than a guarantee. The name refuses instead.
		//
		// It stays bound because it has shipped: it is in runbooks and in
		// profiles on disk, and removing it in the same release that
		// introduces the name would break both with no overlap. parseOptions
		// warns when it is used. See doc/pq-variants-plan.md.
		{Key: OptPQ, Kind: client.OptBool, Help: "DEPRECATED, use `veepin connect pq-ikev2`: offer (not require) ML-KEM-768 as an additional key exchange (RFC 9370)"},
		{Key: OptIPTFS, Kind: client.OptBool, Help: "enable AGGFRAG aggregation and fragmentation (RFC 9347)"},
		{Key: OptIPTFSRate, Kind: client.OptInt, Default: "0", Help: "constant-rate IP-TFS transmission in bytes/sec; 0 = aggregation only"},
		{Key: OptTCP, Kind: client.OptBool, Help: "carry IKE and ESP over one TCP connection (RFC 8229/9329) instead of UDP"},
		client.TUNOpt(OptTUNName),
	})
}
