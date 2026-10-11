// Package ikev1 implements the IKEv1 (ISAKMP/Oakley, RFC 2407/2408/2409) key
// exchange behind two of veepin's protocols. It provides Main Mode and
// Aggressive Mode in both roles with pre-shared-key authentication, XAuth and
// Mode-Config over the ISAKMP Transaction exchange, Quick Mode for the ESP SA in
// either transport or tunnel mode, dead-peer detection (RFC 3706), and NAT-T
// (RFC 3947) so ESP floats to UDP/4500.
//
// Two profiles share all of that:
//
//   - L2TP/IPsec (internal/l2tp) uses Main Mode and a transport-mode SA whose
//     traffic selectors name UDP/1701, which is the exchange every native-OS
//     client speaks (Windows, macOS, iOS, Android) and the mode a stock
//     xl2tpd/strongSwan deployment uses.
//   - Cisco IPsec remote access (internal/cisco) uses Aggressive Mode with a
//     group identity, XAuth for the per-user credentials, Mode-Config for the
//     address assignment, and a tunnel-mode SA carrying bare IP.
//
// The cryptographic primitives (MODP DH, HMAC PRF, AES-CBC) come from
// internal/cryptoutil; the ESP data path is internal/ikev2/esp.
package ikev1

// ISAKMP fixed version octet: major 1, minor 0 (RFC 2408 section 3.1).
const isakmpVersion = 0x10

// isakmpHeaderLen is the fixed ISAKMP header size in octets.
const isakmpHeaderLen = 28

// Exchange types (RFC 2408 section 3.1, RFC 2409, draft-dukes-ike-mode-cfg).
const (
	exchangeAggressive    = 4  // Aggressive Mode
	exchangeMain          = 2  // Identity Protection (Main Mode)
	exchangeInformational = 5  // Informational
	exchangeTransaction   = 6  // ISAKMP Transaction: XAuth and Mode-Config
	exchangeQuick         = 32 // Quick Mode
)

// ISAKMP header flags.
const (
	flagEncryption = 0x01 // payloads after the header are encrypted
	flagCommit     = 0x02
)

// Payload types (RFC 2408 section 3.1, plus NAT-T from RFC 3947).
const (
	payloadNone       = 0
	payloadSA         = 1
	payloadProposal   = 2
	payloadTransform  = 3
	payloadKE         = 4
	payloadID         = 5
	payloadHash       = 8
	payloadNonce      = 10
	payloadNotify     = 11
	payloadDelete     = 12
	payloadVendorID   = 13
	payloadAttribute  = 14 // Attribute, carrying XAuth and Mode-Config
	payloadNATD       = 20 // NAT-Discovery (RFC 3947)
	payloadNATOA      = 21 // NAT-Original-Address (RFC 3947)
	payloadNATDDraft  = 130
	payloadNATOADraft = 131
)

// IPsec DOI (RFC 2407).
const (
	doiIPsec              = 1
	situationIdentityOnly = 1
)

// Protocol IDs (RFC 2407 section 4.4.1).
const (
	protoISAKMP = 1
	protoESP    = 3
)

// Phase-1 (IKE) transform identifier: the only IKE transform is KEY_IKE.
const transformKeyIKE = 1

// ESP transform IDs (RFC 2407 section 4.4.4).
const (
	espTransform3DES = 3
	espTransformAES  = 12 // AES-CBC
)

// Phase-1 SA attribute types (RFC 2409 Appendix A). Encoded TV (basic) unless
// noted; Life Duration is TLV (variable).
const (
	attrEncryption   = 1
	attrHash         = 2
	attrAuthMethod   = 3
	attrGroup        = 4
	attrLifeType     = 11
	attrLifeDuration = 12
	attrKeyLength    = 14
)

// Phase-1 attribute values. authXAuthInitPSK is the extended authentication
// method from draft-ietf-ipsec-isakmp-xauth: it keys exactly as a pre-shared key
// does, and additionally commits both ends to running XAuth before phase 2.
const (
	encrAES          = 7 // AES-CBC
	hashSHA          = 2 // SHA-1
	hashSHA2256      = 4 // SHA2-256
	authPSK          = 1 // pre-shared key
	authXAuthInitPSK = 65001
	groupMODP1024    = 2
	groupMODP2048    = 14
	lifeTypeSeconds  = 1
)

// Phase-2 (IPsec DOI) SA attribute types (RFC 2407 section 4.5).
const (
	ipsecAttrLifeType     = 1
	ipsecAttrLifeDuration = 2
	ipsecAttrGroup        = 3
	ipsecAttrEncapMode    = 4
	ipsecAttrAuthAlg      = 5
	ipsecAttrKeyLength    = 6
)

// Encapsulation modes (RFC 2407 section 4.5, RFC 3947 section 5.2). The draft
// UDP-encapsulated values (61443/61444) are what many peers still send; we
// propose the RFC values and accept either.
const (
	encapTunnel            = 1
	encapTransport         = 2
	encapUDPTunnel         = 3
	encapUDPTransport      = 4
	encapUDPTunnelDraft    = 61443
	encapUDPTransportDraft = 61444
)

// Phase-2 authentication algorithms (RFC 2407 section 4.5).
const (
	authHMACSHA     = 2
	authHMACSHA2256 = 5
)

// ID types (RFC 2407 section 4.6.2.1). ID_KEY_ID is an opaque octet string,
// which is how a remote-access group name travels in Aggressive Mode.
const (
	idIPv4Addr       = 1
	idFQDN           = 2
	idUserFQDN       = 3
	idIPv4AddrSubnet = 4
	idKeyID          = 11
)

// Transaction message types (draft-dukes-ike-mode-cfg section 3.1). REQUEST/REPLY
// is the pull form Mode-Config uses; SET/ACK is the push form XAuth ends with.
const (
	cfgRequest = 1
	cfgReply   = 2
	cfgSet     = 3
	cfgAck     = 4
)

// Mode-Config attributes (RFC 2407 section 4.6.4.1).
const (
	cfgAttrIP4Address = 1
	cfgAttrIP4Netmask = 2
	cfgAttrIP4DNS     = 3
	cfgAttrIP4NBNS    = 4
	cfgAttrExpiry     = 5
	cfgAttrIP4DHCP    = 6
	cfgAttrAppVersion = 7
)

// XAuth attributes (draft-ietf-ipsec-isakmp-xauth-06 section 7.2). They share
// the Attribute payload with Mode-Config, distinguished only by their numbers.
const (
	xauthType         = 16520
	xauthUserName     = 16521
	xauthUserPassword = 16522
	xauthPasscode     = 16523
	xauthMessage      = 16524
	xauthChallenge    = 16525
	xauthDomain       = 16526
	xauthStatus       = 16527
	xauthNextPIN      = 16528
	xauthAnswer       = 16529
)

// XAuth authentication types and statuses.
const (
	xauthTypeGeneric = 0
	xauthStatusFail  = 0
	xauthStatusOK    = 1
)

// Cisco Unity attributes, carried in the same Mode-Config reply. Only the four
// veepin can act on are named; the rest of the block is reserved by the vendor.
const (
	unityBanner       = 28672
	unitySavePasswd   = 28673
	unityDefDomain    = 28674
	unitySplitInclude = 28676
)

// DPD notification types (RFC 3706 section 6). They ride an Informational
// exchange as a Notification payload whose SPI is the ISAKMP cookie pair.
const (
	notifyRUThere    = 36136
	notifyRUThereAck = 36137
)

// ipProtoUDP and l2tpPort are the transport-mode traffic selector for L2TP: the
// tunnel protects UDP datagrams on the L2TP port.
const (
	ipProtoUDP = 17
	l2tpPort   = 1701
)

// ikePort carries IKE before NAT traversal; nattPort carries IKE (behind the
// non-ESP marker) and UDP-encapsulated ESP after the float.
const (
	ikePort  = 500
	nattPort = 4500
)
