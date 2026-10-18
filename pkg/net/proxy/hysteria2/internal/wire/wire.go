// Package wire implements the Hysteria 2 wire format without importing Hysteria Core.
// The QUIC and HTTP/3 transports, session lifetime, and routing are intentionally
// outside this package.
package wire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

const (
	FrameTCPRequest = 0x401
	AuthHost        = "hysteria"
	AuthPath        = "/auth"
	AuthOK          = 233
	HeaderAuth      = "Hysteria-Auth"
	HeaderUDP       = "Hysteria-UDP"
	HeaderReceive   = "Hysteria-CC-RX"
	HeaderPadding   = "Hysteria-Padding"
	MaxAddress      = 2048
	MaxMessage      = 2048
	MaxPadding      = 4096
	MaxDatagram     = 1200
	MaxPacket       = 65535
)

var ErrMalformed = errors.New("hysteria2: malformed wire message")

// ClientAuth and ServerAuth use bytes/s, not bits/s.
type ClientAuth struct {
	Password              string
	ReceiveBytesPerSecond uint64
}

type ServerAuth struct {
	UDPEnabled            bool
	ReceiveBytesPerSecond uint64
	AutoBandwidth         bool
}

func WriteClientAuth(h http.Header, a ClientAuth) error {
	padding, err := randomPadding(256, 2048)
	if err != nil {
		return err
	}
	h.Set(HeaderAuth, a.Password)
	h.Set(HeaderReceive, strconv.FormatUint(a.ReceiveBytesPerSecond, 10))
	h.Set(HeaderPadding, padding)
	return nil
}

func ReadClientAuth(h http.Header) ClientAuth {
	v, _ := strconv.ParseUint(h.Get(HeaderReceive), 10, 64)
	return ClientAuth{Password: h.Get(HeaderAuth), ReceiveBytesPerSecond: v}
}

func WriteServerAuth(h http.Header, a ServerAuth) error {
	padding, err := randomPadding(256, 2048)
	if err != nil {
		return err
	}
	h.Set(HeaderUDP, strconv.FormatBool(a.UDPEnabled))
	if a.AutoBandwidth {
		h.Set(HeaderReceive, "auto")
	} else {
		h.Set(HeaderReceive, strconv.FormatUint(a.ReceiveBytesPerSecond, 10))
	}
	h.Set(HeaderPadding, padding)
	return nil
}

func ReadServerAuth(h http.Header) ServerAuth {
	rx := h.Get(HeaderReceive)
	v, _ := strconv.ParseUint(rx, 10, 64)
	b, _ := strconv.ParseBool(h.Get(HeaderUDP))
	return ServerAuth{UDPEnabled: b, ReceiveBytesPerSecond: v, AutoBandwidth: rx == "auto"}
}

const paddingAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Padding lengths are half-open, as in Hysteria 2's implementation.
func randomPadding(low, high int) (string, error) {
	var r [2]byte
	if _, err := rand.Read(r[:]); err != nil {
		return "", err
	}
	n := low + int(binary.BigEndian.Uint16(r[:]))%(high-low)
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = paddingAlphabet[int(b[i])%len(paddingAlphabet)]
	}
	return string(b), nil
}

// QUIC varints use the top two bits to select a 1, 2, 4 or 8 byte encoding.
func varintLen(v uint64) (int, error) {
	switch {
	case v < 1<<6:
		return 1, nil
	case v < 1<<14:
		return 2, nil
	case v < 1<<30:
		return 4, nil
	case v < 1<<62:
		return 8, nil
	default:
		return 0, fmt.Errorf("%w: oversized QUIC varint", ErrMalformed)
	}
}

func appendVarint(dst []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(dst, byte(v))
	case v < 1<<14:
		return append(dst, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(dst, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(dst, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

func readVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	n := 1 << (first[0] >> 6)
	var buf [8]byte
	buf[0] = first[0] & 0x3f
	if _, err := io.ReadFull(r, buf[1:n]); err != nil {
		return 0, err
	}
	var v uint64
	for _, b := range buf[:n] {
		v = v<<8 | uint64(b)
	}
	return v, nil
}

func readVarintBytes(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, io.ErrUnexpectedEOF
	}
	v := uint64(b[0] & 0x3f)
	for _, x := range b[1:n] {
		v = v<<8 | uint64(x)
	}
	return v, n, nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// WriteTCPRequest writes the Hysteria-specific HTTP/3 stream frame (0x401)
// followed by address and padding.
func WriteTCPRequest(w io.Writer, addr string) error {
	if len(addr) == 0 || len(addr) > MaxAddress {
		return fmt.Errorf("%w: invalid TCP destination", ErrMalformed)
	}
	padding, err := randomPadding(64, 512)
	if err != nil {
		return err
	}
	b := make([]byte, 0, 16+len(addr)+len(padding))
	b = appendVarint(b, FrameTCPRequest)
	b = appendVarint(b, uint64(len(addr)))
	b = append(b, addr...)
	b = appendVarint(b, uint64(len(padding)))
	b = append(b, padding...)
	return writeFull(w, b)
}

// ReadTCPRequest consumes the type (0x401). HTTP/3 dispatchers that already
// consumed the type should call ReadTCPRequestBody instead.
func ReadTCPRequest(r io.Reader) (string, error) {
	v, err := readVarint(r)
	if err != nil {
		return "", err
	}
	if v != FrameTCPRequest {
		return "", fmt.Errorf("%w: unexpected TCP frame %#x", ErrMalformed, v)
	}
	return ReadTCPRequestBody(r)
}

func ReadTCPRequestBody(r io.Reader) (string, error) {
	return readPaddedString(r, MaxAddress, true)
}

func readPaddedString(r io.Reader, maximum int, nonempty bool) (string, error) {
	n, err := readVarint(r)
	if err != nil {
		return "", err
	}
	if n > uint64(maximum) || (nonempty && n == 0) {
		return "", fmt.Errorf("%w: invalid string length", ErrMalformed)
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	padding, err := readVarint(r)
	if err != nil {
		return "", err
	}
	if padding > MaxPadding {
		return "", fmt.Errorf("%w: invalid padding length", ErrMalformed)
	}
	if _, err := io.CopyN(io.Discard, r, int64(padding)); err != nil {
		return "", err
	}
	return string(b), nil
}

func WriteTCPResponse(w io.Writer, ok bool, message string) error {
	if len(message) > MaxMessage {
		return fmt.Errorf("%w: oversized response", ErrMalformed)
	}
	padding, err := randomPadding(128, 1024)
	if err != nil {
		return err
	}
	b := make([]byte, 0, 16+len(message)+len(padding))
	if ok {
		b = append(b, 0)
	} else {
		b = append(b, 1)
	}
	b = appendVarint(b, uint64(len(message)))
	b = append(b, message...)
	b = appendVarint(b, uint64(len(padding)))
	b = append(b, padding...)
	return writeFull(w, b)
}

func ReadTCPResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", err
	}
	if status[0] > 1 {
		return false, "", fmt.Errorf("%w: invalid status", ErrMalformed)
	}
	msg, err := readPaddedString(r, MaxMessage, false)
	return status[0] == 0, msg, err
}
