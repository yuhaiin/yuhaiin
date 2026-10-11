package payload

import (
	"encoding/binary"
	"fmt"
	"net"
)

// --- Key Exchange (RFC 7296 3.4) ---

// KEPayload carries a DH group and the public key material.
type KEPayload struct {
	Group   uint16
	KeyData []byte
}

// MarshalKE encodes a KE payload body.
func MarshalKE(ke KEPayload) []byte {
	out := make([]byte, 4+len(ke.KeyData))
	binary.BigEndian.PutUint16(out[0:2], ke.Group)
	// out[2:4] reserved
	copy(out[4:], ke.KeyData)
	return out
}

// ParseKE decodes a KE payload body.
func ParseKE(buf []byte) (KEPayload, error) {
	if len(buf) < 4 {
		return KEPayload{}, ErrTruncated
	}
	return KEPayload{
		Group:   binary.BigEndian.Uint16(buf[0:2]),
		KeyData: append([]byte(nil), buf[4:]...),
	}, nil
}

// --- Nonce (RFC 7296 3.9) ---

// MarshalNonce encodes a nonce payload body (raw nonce bytes).
func MarshalNonce(nonce []byte) []byte {
	return append([]byte(nil), nonce...)
}

// ParseNonce returns the nonce bytes.
func ParseNonce(buf []byte) []byte {
	return append([]byte(nil), buf...)
}

// --- Notify (RFC 7296 3.10) ---

// NotifyPayload is a decoded Notify payload.
type NotifyPayload struct {
	Protocol ProtocolID
	Type     NotifyType
	SPI      []byte
	Data     []byte
}

// MarshalNotify encodes a Notify payload body.
func MarshalNotify(n NotifyPayload) []byte {
	out := make([]byte, 4+len(n.SPI)+len(n.Data))
	out[0] = byte(n.Protocol)
	out[1] = byte(len(n.SPI))
	binary.BigEndian.PutUint16(out[2:4], uint16(n.Type))
	copy(out[4:], n.SPI)
	copy(out[4+len(n.SPI):], n.Data)
	return out
}

// ParseNotify decodes a Notify payload body.
func ParseNotify(buf []byte) (NotifyPayload, error) {
	if len(buf) < 4 {
		return NotifyPayload{}, ErrTruncated
	}
	spiSize := int(buf[1])
	if 4+spiSize > len(buf) {
		return NotifyPayload{}, ErrTruncated
	}
	return NotifyPayload{
		Protocol: ProtocolID(buf[0]),
		Type:     NotifyType(binary.BigEndian.Uint16(buf[2:4])),
		SPI:      append([]byte(nil), buf[4:4+spiSize]...),
		Data:     append([]byte(nil), buf[4+spiSize:]...),
	}, nil
}

// --- Identification (RFC 7296 3.5) ---

// IDPayload is a decoded IDi/IDr payload.
type IDPayload struct {
	Type IDType
	Data []byte
}

// MarshalID encodes an ID payload body.
func MarshalID(id IDPayload) []byte {
	out := make([]byte, 4+len(id.Data))
	out[0] = byte(id.Type)
	// out[1:4] reserved
	copy(out[4:], id.Data)
	return out
}

// ParseID decodes an ID payload body.
func ParseID(buf []byte) (IDPayload, error) {
	if len(buf) < 4 {
		return IDPayload{}, ErrTruncated
	}
	return IDPayload{
		Type: IDType(buf[0]),
		Data: append([]byte(nil), buf[4:]...),
	}, nil
}

// --- Certificate (RFC 7296 3.6) ---

// CertPayload is a decoded CERT payload: an encoding byte plus the certificate
// data (a DER-encoded X.509 certificate for CertX509Signature).
type CertPayload struct {
	Encoding CertEncoding
	Data     []byte
}

// MarshalCert encodes a CERT payload body.
func MarshalCert(c CertPayload) []byte {
	out := make([]byte, 1+len(c.Data))
	out[0] = byte(c.Encoding)
	copy(out[1:], c.Data)
	return out
}

// ParseCert decodes a CERT payload body.
func ParseCert(buf []byte) (CertPayload, error) {
	if len(buf) < 1 {
		return CertPayload{}, ErrTruncated
	}
	return CertPayload{
		Encoding: CertEncoding(buf[0]),
		Data:     append([]byte(nil), buf[1:]...),
	}, nil
}

// --- Certificate Request (RFC 7296 3.7) ---

// CertReqPayload is a decoded CERTREQ payload: an encoding byte plus the
// Certification Authority field. For CertX509Signature that field is a
// concatenation of 20-octet SHA-1 hashes of trusted CA public keys (empty means
// "any trusted CA").
type CertReqPayload struct {
	Encoding CertEncoding
	CAs      []byte
}

// MarshalCertReq encodes a CERTREQ payload body.
func MarshalCertReq(c CertReqPayload) []byte {
	out := make([]byte, 1+len(c.CAs))
	out[0] = byte(c.Encoding)
	copy(out[1:], c.CAs)
	return out
}

// ParseCertReq decodes a CERTREQ payload body.
func ParseCertReq(buf []byte) (CertReqPayload, error) {
	if len(buf) < 1 {
		return CertReqPayload{}, ErrTruncated
	}
	return CertReqPayload{
		Encoding: CertEncoding(buf[0]),
		CAs:      append([]byte(nil), buf[1:]...),
	}, nil
}

// --- Authentication (RFC 7296 3.8) ---

// AuthPayload is a decoded AUTH payload.
type AuthPayload struct {
	Method AuthMethod
	Data   []byte
}

// MarshalAuth encodes an AUTH payload body.
func MarshalAuth(a AuthPayload) []byte {
	out := make([]byte, 4+len(a.Data))
	out[0] = byte(a.Method)
	// out[1:4] reserved
	copy(out[4:], a.Data)
	return out
}

// ParseAuth decodes an AUTH payload body.
func ParseAuth(buf []byte) (AuthPayload, error) {
	if len(buf) < 4 {
		return AuthPayload{}, ErrTruncated
	}
	return AuthPayload{
		Method: AuthMethod(buf[0]),
		Data:   append([]byte(nil), buf[4:]...),
	}, nil
}

// --- Traffic Selectors (RFC 7296 3.13) ---

// TrafficSelector describes a range of addresses/ports/protocol.
type TrafficSelector struct {
	Type       TSType
	IPProtocol uint8
	StartPort  uint16
	EndPort    uint16
	StartAddr  net.IP
	EndAddr    net.IP
}

// TSPayload is a decoded TSi/TSr payload: a set of selectors.
type TSPayload struct {
	Selectors []TrafficSelector
}

// MarshalTS encodes a TS payload body.
func MarshalTS(ts TSPayload) []byte {
	out := make([]byte, 4)
	out[0] = byte(len(ts.Selectors))
	// out[1:4] reserved
	for _, sel := range ts.Selectors {
		out = append(out, marshalSelector(sel)...)
	}
	return out
}

func marshalSelector(s TrafficSelector) []byte {
	var addrLen int
	switch s.Type {
	case TSIPv4AddrRange:
		addrLen = 4
	case TSIPv6AddrRange:
		addrLen = 16
	}
	total := 8 + 2*addrLen
	out := make([]byte, 8)
	out[0] = byte(s.Type)
	out[1] = s.IPProtocol
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	binary.BigEndian.PutUint16(out[4:6], s.StartPort)
	binary.BigEndian.PutUint16(out[6:8], s.EndPort)
	start := s.StartAddr
	end := s.EndAddr
	if addrLen == 4 {
		start = start.To4()
		end = end.To4()
	} else {
		start = start.To16()
		end = end.To16()
	}
	out = append(out, start...)
	out = append(out, end...)
	return out
}

// ParseTS decodes a TS payload body.
func ParseTS(buf []byte) (TSPayload, error) {
	if len(buf) < 4 {
		return TSPayload{}, ErrTruncated
	}
	count := int(buf[0])
	off := 4
	var ts TSPayload
	for i := 0; i < count; i++ {
		if off+8 > len(buf) {
			return ts, ErrTruncated
		}
		selType := TSType(buf[off])
		proto := buf[off+1]
		slen := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		if slen < 8 || off+slen > len(buf) {
			return ts, fmt.Errorf("payload: bad selector length %d", slen)
		}
		startPort := binary.BigEndian.Uint16(buf[off+4 : off+6])
		endPort := binary.BigEndian.Uint16(buf[off+6 : off+8])
		addrLen := (slen - 8) / 2
		startAddr := append(net.IP(nil), buf[off+8:off+8+addrLen]...)
		endAddr := append(net.IP(nil), buf[off+8+addrLen:off+8+2*addrLen]...)
		ts.Selectors = append(ts.Selectors, TrafficSelector{
			Type:       selType,
			IPProtocol: proto,
			StartPort:  startPort,
			EndPort:    endPort,
			StartAddr:  startAddr,
			EndAddr:    endAddr,
		})
		off += slen
	}
	return ts, nil
}

// --- Delete (RFC 7296 3.11) ---

// DeletePayload is a decoded Delete payload.
type DeletePayload struct {
	Protocol ProtocolID
	SPISize  uint8
	SPIs     [][]byte
}

// MarshalDelete encodes a Delete payload body.
func MarshalDelete(d DeletePayload) []byte {
	out := make([]byte, 4)
	out[0] = byte(d.Protocol)
	out[1] = d.SPISize
	binary.BigEndian.PutUint16(out[2:4], uint16(len(d.SPIs)))
	for _, spi := range d.SPIs {
		out = append(out, spi...)
	}
	return out
}

// ParseDelete decodes a Delete payload body.
func ParseDelete(buf []byte) (DeletePayload, error) {
	if len(buf) < 4 {
		return DeletePayload{}, ErrTruncated
	}
	d := DeletePayload{
		Protocol: ProtocolID(buf[0]),
		SPISize:  buf[1],
	}
	n := int(binary.BigEndian.Uint16(buf[2:4]))
	off := 4
	sz := int(d.SPISize)
	for i := 0; i < n; i++ {
		if off+sz > len(buf) {
			return d, ErrTruncated
		}
		d.SPIs = append(d.SPIs, append([]byte(nil), buf[off:off+sz]...))
		off += sz
	}
	return d, nil
}

// --- Configuration Payload (RFC 7296 3.15) ---

// CFGAttr is a single configuration attribute (type + value).
type CFGAttr struct {
	Type  CFGAttrType
	Value []byte
}

// CPPayload is a decoded Configuration payload.
type CPPayload struct {
	Type  CFGType
	Attrs []CFGAttr
}

// MarshalCP encodes a Configuration payload body.
func MarshalCP(cp CPPayload) []byte {
	out := make([]byte, 4)
	out[0] = byte(cp.Type)
	// out[1:4] reserved
	for _, a := range cp.Attrs {
		var hdr [4]byte
		// High bit of the type field is reserved (0); 15-bit type.
		binary.BigEndian.PutUint16(hdr[0:2], uint16(a.Type)&0x7fff)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(a.Value)))
		out = append(out, hdr[:]...)
		out = append(out, a.Value...)
	}
	return out
}

// ParseCP decodes a Configuration payload body.
func ParseCP(buf []byte) (CPPayload, error) {
	if len(buf) < 4 {
		return CPPayload{}, ErrTruncated
	}
	cp := CPPayload{Type: CFGType(buf[0])}
	off := 4
	for off+4 <= len(buf) {
		atype := binary.BigEndian.Uint16(buf[off:off+2]) & 0x7fff
		alen := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		off += 4
		if off+alen > len(buf) {
			return cp, ErrTruncated
		}
		cp.Attrs = append(cp.Attrs, CFGAttr{
			Type:  CFGAttrType(atype),
			Value: append([]byte(nil), buf[off:off+alen]...),
		})
		off += alen
	}
	return cp, nil
}

// AttrValue returns the value of the first attribute of type t, or nil.
func (cp *CPPayload) AttrValue(t CFGAttrType) ([]byte, bool) {
	for _, a := range cp.Attrs {
		if a.Type == t {
			return a.Value, true
		}
	}
	return nil, false
}
