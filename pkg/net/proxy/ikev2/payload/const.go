// Package payload implements IKEv2 wire-format encoding/decoding of the
// IKE header and payloads as defined by RFC 7296.
package payload

// ExchangeType identifies an IKEv2 exchange (RFC 7296 section 3.1).
type ExchangeType uint8

const (
	IKE_SA_INIT      ExchangeType = 34
	IKE_AUTH         ExchangeType = 35
	CREATE_CHILD_SA  ExchangeType = 36
	INFORMATIONAL    ExchangeType = 37
	IKE_INTERMEDIATE ExchangeType = 43 // RFC 9242
)

func (e ExchangeType) String() string {
	switch e {
	case IKE_SA_INIT:
		return "IKE_SA_INIT"
	case IKE_AUTH:
		return "IKE_AUTH"
	case CREATE_CHILD_SA:
		return "CREATE_CHILD_SA"
	case INFORMATIONAL:
		return "INFORMATIONAL"
	case IKE_INTERMEDIATE:
		return "IKE_INTERMEDIATE"
	default:
		return "UNKNOWN_EXCHANGE"
	}
}

// Flags in the IKE header (RFC 7296 section 3.1).
const (
	FlagInitiator = 1 << 3 // 'I': set when sender is the original initiator.
	FlagVersion   = 1 << 4 // 'V': higher version supported.
	FlagResponse  = 1 << 5 // 'R': message is a response.
)

// PayloadType identifies each IKEv2 payload (RFC 7296 section 3.2).
type PayloadType uint8

const (
	NoNextPayload PayloadType = 0
	TypeSA        PayloadType = 33 // Security Association
	TypeKE        PayloadType = 34 // Key Exchange
	TypeIDi       PayloadType = 35 // Identification - Initiator
	TypeIDr       PayloadType = 36 // Identification - Responder
	TypeCERT      PayloadType = 37 // Certificate
	TypeCERTREQ   PayloadType = 38 // Certificate Request
	TypeAUTH      PayloadType = 39 // Authentication
	TypeNonce     PayloadType = 40 // Nonce
	TypeNotify    PayloadType = 41 // Notify
	TypeDelete    PayloadType = 42 // Delete
	TypeVendorID  PayloadType = 43 // Vendor ID
	TypeTSi       PayloadType = 44 // Traffic Selector - Initiator
	TypeTSr       PayloadType = 45 // Traffic Selector - Responder
	TypeSK        PayloadType = 46 // Encrypted and Authenticated
	TypeCP        PayloadType = 47 // Configuration
	TypeEAP       PayloadType = 48 // Extensible Authentication
	TypeSKF       PayloadType = 53 // Encrypted and Authenticated Fragment (RFC 7383)
)

func (p PayloadType) String() string {
	switch p {
	case NoNextPayload:
		return "None"
	case TypeSA:
		return "SA"
	case TypeKE:
		return "KE"
	case TypeIDi:
		return "IDi"
	case TypeIDr:
		return "IDr"
	case TypeCERT:
		return "CERT"
	case TypeCERTREQ:
		return "CERTREQ"
	case TypeAUTH:
		return "AUTH"
	case TypeNonce:
		return "Nonce"
	case TypeNotify:
		return "Notify"
	case TypeDelete:
		return "Delete"
	case TypeVendorID:
		return "VendorID"
	case TypeTSi:
		return "TSi"
	case TypeTSr:
		return "TSr"
	case TypeSK:
		return "SK"
	case TypeCP:
		return "CP"
	case TypeEAP:
		return "EAP"
	case TypeSKF:
		return "SKF"
	default:
		return "UNKNOWN_PAYLOAD"
	}
}

// ProtocolID values used in SA proposals, Notify and Delete payloads
// (RFC 7296 section 3.3.1).
type ProtocolID uint8

const (
	ProtoNone ProtocolID = 0
	ProtoIKE  ProtocolID = 1
	ProtoAH   ProtocolID = 2
	ProtoESP  ProtocolID = 3
)

// TransformType categories inside an SA proposal (RFC 7296 section 3.3.2).
type TransformType uint8

const (
	TransformENCR  TransformType = 1 // Encryption Algorithm
	TransformPRF   TransformType = 2 // Pseudorandom Function
	TransformINTEG TransformType = 3 // Integrity Algorithm
	TransformDH    TransformType = 4 // Key Exchange Method (was Diffie-Hellman Group)
	TransformESN   TransformType = 5 // Sequence Numbers

	// Additional Key Exchange transforms (RFC 9370 section 2.1). These are
	// negotiated alongside the mandatory KE transform and each names a group
	// from the same registry as TransformDH.
	TransformADDKE1 TransformType = 6
	TransformADDKE2 TransformType = 7
	TransformADDKE3 TransformType = 8
	TransformADDKE4 TransformType = 9
	TransformADDKE5 TransformType = 10
	TransformADDKE6 TransformType = 11
	TransformADDKE7 TransformType = 12
)

// Encryption transform IDs (IANA IKEv2 registry).
const (
	ENCR_AES_CBC    uint16 = 12
	ENCR_AES_GCM_16 uint16 = 20 // AES-GCM with 16-octet ICV
	ENCR_CHACHA20_P uint16 = 28 // ChaCha20-Poly1305
)

// PRF transform IDs.
const (
	PRF_HMAC_SHA1     uint16 = 2
	PRF_HMAC_SHA2_256 uint16 = 5
	PRF_HMAC_SHA2_384 uint16 = 6
	PRF_HMAC_SHA2_512 uint16 = 7
)

// Integrity transform IDs.
const (
	AUTH_HMAC_SHA1_96      uint16 = 2
	AUTH_HMAC_SHA2_256_128 uint16 = 12
	AUTH_HMAC_SHA2_384_192 uint16 = 13
	AUTH_HMAC_SHA2_512_256 uint16 = 14
)

// Diffie-Hellman group IDs (RFC 7296 / RFC 8247).
const (
	DH_MODP_2048  uint16 = 14
	DH_ECP_256    uint16 = 19
	DH_ECP_384    uint16 = 20
	DH_ECP_521    uint16 = 21
	DH_CURVE25519 uint16 = 31

	// Post-quantum KEM group IDs (IANA IKEv2 registry, RFC-ietf-ipsecme-ikev2-mlkem).
	MLKEM512  uint16 = 35
	MLKEM768  uint16 = 36
	MLKEM1024 uint16 = 37
)

// ESN transform IDs.
const (
	ESN_NONE uint16 = 0
	ESN_YES  uint16 = 1
)

// Attribute type for key length inside a transform (RFC 7296 3.3.5).
const AttrKeyLength uint16 = 14

// AuthMethod values in the AUTH payload (RFC 7296 section 3.8).
type AuthMethod uint8

const (
	AuthRSASig       AuthMethod = 1
	AuthSharedKeyMIC AuthMethod = 2 // PSK
	AuthDSSSig       AuthMethod = 3
	AuthDigitalSig   AuthMethod = 14 // RFC 7427
)

// IDType values in the ID payload (RFC 7296 section 3.5).
type IDType uint8

const (
	IDIPv4Addr  IDType = 1
	IDFQDN      IDType = 2
	IDRFC822    IDType = 3
	IDIPv6Addr  IDType = 5
	IDDERASN1DN IDType = 9
	IDKeyID     IDType = 11
)

// NotifyType values (RFC 7296 section 3.10.1 + extensions).
type NotifyType uint16

const (
	// Error types (0-16383).
	UnsupportedCriticalPayload NotifyType = 1
	InvalidIKESPI              NotifyType = 4
	InvalidMajorVersion        NotifyType = 5
	InvalidSyntax              NotifyType = 7
	InvalidMessageID           NotifyType = 9
	InvalidSPI                 NotifyType = 11
	NoProposalChosen           NotifyType = 14
	InvalidKEPayload           NotifyType = 17
	AuthenticationFailed       NotifyType = 24
	SinglePairRequired         NotifyType = 34
	NoAdditionalSAs            NotifyType = 35
	InternalAddressFailure     NotifyType = 36
	FailedCPRequired           NotifyType = 37
	TSUnacceptable             NotifyType = 38
	InvalidSelectors           NotifyType = 39
	TemporaryFailure           NotifyType = 43
	ChildSANotFound            NotifyType = 44

	// Status types (16384-65535).
	InitialContact            NotifyType = 16384
	SetWindowSize             NotifyType = 16385
	AdditionalTSPossible      NotifyType = 16386
	IPCompSupported           NotifyType = 16387
	NATDetectionSourceIP      NotifyType = 16388
	NATDetectionDestinationIP NotifyType = 16389
	Cookie                    NotifyType = 16390
	UseTransportMode          NotifyType = 16391
	HTTPCertLookupSupported   NotifyType = 16392
	RekeySA                   NotifyType = 16393
	ESPTFCPaddingNotSupported NotifyType = 16394
	NonFirstFragmentsAlso     NotifyType = 16395
	MobikeSupported           NotifyType = 16396
	// MOBIKE address agility (RFC 4555).
	AdditionalIP4Address  NotifyType = 16397
	AdditionalIP6Address  NotifyType = 16398
	NoAdditionalAddresses NotifyType = 16399
	UpdateSAAddresses     NotifyType = 16400
	Cookie2               NotifyType = 16401
	NoNATsAllowed         NotifyType = 16402

	// IKEFragmentationSupported (RFC 7383): advertised in IKE_SA_INIT by both
	// peers to permit IKE-layer fragmentation of later protected messages.
	IKEFragmentationSupported NotifyType = 16430

	SignatureHashAlgorithms NotifyType = 16431

	// IntermediateExchangeSupported (RFC 9242 section 3.1): advertised in
	// IKE_SA_INIT to indicate the endpoint can process IKE_INTERMEDIATE exchanges.
	// 16438, per the IANA registry — not 16444, which is CHILDLESS_IKEV2_SUPPORTED.
	IntermediateExchangeSupported NotifyType = 16438

	// UseAggFrag (RFC 9347 section 3.1): advertised by both peers to enable
	// AGGFRAG aggregation and fragmentation for the Child SA.
	UseAggFrag NotifyType = 16442
)

// CertEncoding values in CERT / CERTREQ payloads (RFC 7296 section 3.6). Only
// X.509 signature certificates are used here.
type CertEncoding uint8

const (
	CertX509Signature CertEncoding = 4
)

// Hash-algorithm identifiers carried in a SIGNATURE_HASH_ALGORITHMS notify
// (RFC 7427 section 4): a peer lists the hashes it will accept in an RFC 7427
// Digital Signature (AUTH method 14).
const (
	HashSHA1   uint16 = 1
	HashSHA256 uint16 = 2
	HashSHA384 uint16 = 3
	HashSHA512 uint16 = 4
	// HashIdentity (RFC 9593) means the signature scheme hashes the message
	// itself, so no external hash is applied before signing. It is what
	// draft-ietf-ipsecme-ikev2-pqc-auth requires a peer to advertise before
	// ML-DSA can be selected: ML-DSA is not "sign a SHA-512 digest", it takes
	// the message. Omit it and a conforming peer will never choose ML-DSA.
	HashIdentity uint16 = 5
)

// Traffic-selector types (RFC 7296 section 3.13.1).
type TSType uint8

const (
	TSIPv4AddrRange TSType = 7
	TSIPv6AddrRange TSType = 8
)

// IP protocol numbers used in traffic selectors.
const (
	IPProtoAny uint8 = 0
	IPProtoTCP uint8 = 6
	IPProtoUDP uint8 = 17
)

// Configuration payload types (RFC 7296 section 3.15.1).
type CFGType uint8

const (
	CFGRequest CFGType = 1
	CFGReply   CFGType = 2
	CFGSet     CFGType = 3
	CFGAck     CFGType = 4
)

// Configuration attribute types (RFC 7296 section 3.15.1 + RFC 7296 IANA).
type CFGAttrType uint16

const (
	CFGInternalIP4Address CFGAttrType = 1
	CFGInternalIP4Netmask CFGAttrType = 2
	CFGInternalIP4DNS     CFGAttrType = 3
	CFGInternalIP4NBNS    CFGAttrType = 4
	CFGInternalIP4DHCP    CFGAttrType = 6
	CFGApplicationVersion CFGAttrType = 7
	CFGInternalIP6Address CFGAttrType = 8
	CFGInternalIP6DNS     CFGAttrType = 10
	CFGInternalIP4Subnet  CFGAttrType = 13
	CFGInternalIP6Subnet  CFGAttrType = 15
)
