package resolver

import (
	"errors"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	TypeSVCB  dnsmessage.Type = 64
	TypeHTTPS dnsmessage.Type = 65
)

// An SVCBResource is an SVCB Resource record.
type SVCBResource struct {
	Params   []Param
	Priority uint16
	Target   dnsmessage.Name
}

type ParamKey uint16

// GoString implements fmt.GoStringer.GoString.
func (t ParamKey) GoString() string {
	if n, ok := paramGoNames[t]; ok {
		return "dnsmessage." + n
	}
	return printUint16(uint16(t))
}

const (
	ParamMandatory     ParamKey = 0
	ParamALPN          ParamKey = 1
	ParamNoDefaultALPN ParamKey = 2
	ParamPort          ParamKey = 3
	ParamIPv4Hint      ParamKey = 4
	ParamECHConfig     ParamKey = 5
	ParamIPv6Hint      ParamKey = 6
)

var paramNames = map[ParamKey]string{
	ParamMandatory:     "mandatory",
	ParamALPN:          "alpn",
	ParamNoDefaultALPN: "no-default-alpn",
	ParamPort:          "port",
	ParamIPv4Hint:      "ipv4hint",
	ParamECHConfig:     "echconfig",
	ParamIPv6Hint:      "ipv6hint",
}

var paramGoNames = map[ParamKey]string{
	ParamMandatory:     "ParamMandatory",
	ParamALPN:          "ParamALPN",
	ParamNoDefaultALPN: "ParamNoDefaultALPN",
	ParamPort:          "ParamPort",
	ParamIPv4Hint:      "ParamIPv4Hint",
	ParamECHConfig:     "ParamECHConfig",
	ParamIPv6Hint:      "ParamIPv6Hint",
}

type Param struct {
	Value []byte
	Key   ParamKey
}

func (p Param) GoString() string {
	return "dnsmessage.Param{" +
		"Key: " + p.Key.GoString() + ", " +
		`Value: "` + printString(p.Value) + `"}`
}

func (r *SVCBResource) realType() dnsmessage.Type {
	return 64
}

// GoString implements fmt.GoStringer.GoString.
func (r *SVCBResource) GoString() string {
	s := "dnsmessage.SVCBResource{" +
		"Priority: " + printUint16(r.Priority) + ", " +
		"Target: " + r.Target.GoString() +
		"Params: []dnsmessage.Param{"
	if len(r.Params) == 0 {
		return s + "}}"
	}
	s += r.Params[0].GoString()
	for _, p := range r.Params[1:] {
		s += ", " + p.GoString()
	}
	return s + "}}"
}

// Internal constants.
const (
	// packStartingCap is the default initial buffer size allocated during
	// packing.
	//
	// The starting capacity doesn't matter too much, but most DNS responses
	// Will be <= 512 bytes as it is the limit for DNS over UDP.
	packStartingCap = 512

	// uint16Len is the length (in bytes) of a uint16.
	uint16Len = 2

	// uint32Len is the length (in bytes) of a uint32.
	uint32Len = 4

	// headerLen is the length (in bytes) of a DNS header.
	//
	// A header is comprised of 6 uint16s and no padding.
	headerLen = 6 * uint16Len
)

type nestedError struct {

	// err is the nested error.
	err error
	// s is the current level's error message.
	s string
}

// nestedError implements error.Error.
func (e *nestedError) Error() string {
	return e.s + ": " + e.err.Error()
}

func skipName(msg []byte, off int) (int, error) {
	// newOff is the offset where the next record will start. Pointers lead
	// to data that belongs to other names and thus doesn't count towards to
	// the usage of this name.
	newOff := off

Loop:
	for {
		if newOff >= len(msg) {
			return off, errors.New("errBaseLen")
		}
		c := int(msg[newOff])
		newOff++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 {
				// A zero length signals the end of the name.
				break Loop
			}
			// literal string
			newOff += c
			if newOff > len(msg) {
				return off, errors.New("errCalcLen")
			}
		case 0xC0:
			// Pointer to somewhere else in msg.

			// Pointers are two bytes.
			newOff++

			// Don't follow the pointer as the data here has ended.
			break Loop
		default:
			// Prefixes 0x80 and 0x40 are reserved.
			return off, errors.New("errReserved")
		}
	}

	return newOff, nil
}

func unpackSVCBResource(msg []byte, off int, length uint16) (SVCBResource, error) {
	endOff := off + int(length)
	priority, off, err := unpackUint16(msg, off)
	if err != nil {
		return SVCBResource{}, &nestedError{err, "Priority"}
	}
	var target dnsmessage.Name
	if off, err = skipName(msg, off); err != nil {
		return SVCBResource{}, &nestedError{err, "Target"}
	}
	var params []Param
	for off < endOff {
		var err error
		var p Param
		var k uint16
		k, off, err = unpackUint16(msg, off)
		p.Key = ParamKey(k)
		if err != nil {
			return SVCBResource{}, &nestedError{err, "Key"}
		}
		var l uint16
		l, off, err = unpackUint16(msg, off)
		if err != nil {
			return SVCBResource{}, &nestedError{err, "Value"}
		}
		p.Value = make([]byte, l)
		if copy(p.Value, msg[off:]) != int(l) {
			return SVCBResource{}, &nestedError{errors.New("insufficient data for calculated length type"), "Value"}
		}
		off += int(l)
		params = append(params, p)
	}
	return SVCBResource{params, priority, target}, nil
}

type HTTPSResource struct {
	Params   []Param
	Priority uint16
	Target   dnsmessage.Name
}

func (r *HTTPSResource) realType() dnsmessage.Type {
	return 65
}

// GoString implements fmt.GoStringer.GoString.
func (r *HTTPSResource) GoString() string {
	s := "dnsmessage.HTTPSResource{" +
		"Priority: " + printUint16(r.Priority) + ", " +
		"Target: " + r.Target.GoString() +
		"Params: []dnsmessage.Param{"
	if len(r.Params) == 0 {
		return s + "}}"
	}
	s += r.Params[0].GoString()
	for _, p := range r.Params[1:] {
		s += ", " + p.GoString()
	}
	return s + "}}"
}

func unpackHTTPSResource(msg []byte, off int, length uint16) (HTTPSResource, error) {
	r, err := unpackSVCBResource(msg, off, length)
	return HTTPSResource(r), err
}

const hexDigits = "0123456789abcdef"

func printString(str []byte) string {
	buf := make([]byte, 0, len(str))
	for i := range str {
		c := str[i]
		if c == '.' || c == '-' || c == ' ' ||
			'A' <= c && c <= 'Z' ||
			'a' <= c && c <= 'z' ||
			'0' <= c && c <= '9' {
			buf = append(buf, c)
			continue
		}

		upper := c >> 4
		lower := (c << 4) >> 4
		buf = append(
			buf,
			'\\',
			'x',
			hexDigits[upper],
			hexDigits[lower],
		)
	}
	return string(buf)
}

func printUint16(i uint16) string {
	return printUint32(uint32(i))
}

func printUint32(i uint32) string {
	// Max value is 4294967295.
	buf := make([]byte, 10)
	for b, d := buf, uint32(1000000000); d > 0; d /= 10 {
		b[0] = byte(i/d%10 + '0')
		if b[0] == '0' && len(b) == len(buf) && len(buf) > 1 {
			buf = buf[1:]
		}
		b = b[1:]
		i %= d
	}
	return string(buf)
}

func unpackUint16(msg []byte, off int) (uint16, int, error) {
	if off+uint16Len > len(msg) {
		return 0, off, errors.New("errBaseLen")
	}
	return uint16(msg[off])<<8 | uint16(msg[off+1]), off + uint16Len, nil
}
