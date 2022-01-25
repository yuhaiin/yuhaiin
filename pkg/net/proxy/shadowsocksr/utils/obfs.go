package ssr

import (
	"encoding/binary"
	"errors"
	"unsafe"
)

const ObfsHMACSHA1Len = 10

var (
	ErrAuthSHA1v4CRC32Error                = errors.New("auth_sha1_v4 post decrypt data crc32 error")
	ErrAuthSHA1v4DataLengthError           = errors.New("auth_sha1_v4 post decrypt data length error")
	ErrAuthSHA1v4IncorrectChecksum         = errors.New("auth_sha1_v4 post decrypt incorrect checksum")
	ErrAuthAES128IncorrectHMAC             = errors.New("auth_aes128_* post decrypt incorrect hmac")
	ErrAuthAES128DataLengthError           = errors.New("auth_aes128_* post decrypt length mismatch")
	ErrAuthChainDataLengthError            = errors.New("auth_chain_* post decrypt length mismatch")
	ErrAuthChainIncorrectHMAC              = errors.New("auth_chain_* post decrypt incorrect hmac")
	ErrAuthAES128IncorrectChecksum         = errors.New("auth_aes128_* post decrypt incorrect checksum")
	ErrAuthAES128PosOutOfRange             = errors.New("auth_aes128_* post decrypt pos out of range")
	ErrTLS12TicketAuthTooShortData         = errors.New("tls1.2_ticket_auth too short data")
	ErrTLS12TicketAuthHMACError            = errors.New("tls1.2_ticket_auth hmac verifying failed")
	ErrTLS12TicketAuthIncorrectMagicNumber = errors.New("tls1.2_ticket_auth incorrect magic number")
)

type ServerInfo struct {
	Host      string
	Port      uint16
	Param     string
	IV        []byte
	IVLen     int
	RecvIV    []byte
	RecvIVLen int
	Key       []byte
	KeyLen    int
	HeadLen   int
	TcpMss    int
	Overhead  int
}

func GetHeadSize(data []byte, defaultValue int) int {
	if data == nil || len(data) < 2 {
		return defaultValue
	}
	headType := data[0] & 0x07
	switch headType {
	case 1:
		// IPv4 1+4+2
		return 7
	case 4:
		// IPv6 1+16+2
		return 19
	case 3:
		// domain name, variant length
		return 4 + int(data[1])
	}

	return defaultValue
}

func (s *ServerInfo) SetHeadLen(data []byte, defaultValue int) {
	s.HeadLen = GetHeadSize(data, defaultValue)
}

func IsLittleEndian() bool {
	const N int = int(unsafe.Sizeof(0))
	x := 0x1234
	p := unsafe.Pointer(&x)
	p2 := (*[N]byte)(p)
	if p2[0] == 0 {
		return false
	} else {
		return true
	}
}

type Shift128plusContext struct {
	v [2]uint64
}

func (ctx *Shift128plusContext) InitFromBin(bin []byte) {
	var fillBin [16]byte
	copy(fillBin[:], bin)

	ctx.v[0] = binary.LittleEndian.Uint64(fillBin[:8])
	ctx.v[1] = binary.LittleEndian.Uint64(fillBin[8:])
}

func (ctx *Shift128plusContext) InitFromBinDatalen(bin []byte, datalen int) {
	var fillBin [16]byte
	copy(fillBin[:], bin)
	binary.LittleEndian.PutUint16(fillBin[:2], uint16(datalen))

	ctx.v[0] = binary.LittleEndian.Uint64(fillBin[:8])
	ctx.v[1] = binary.LittleEndian.Uint64(fillBin[8:])

	for i := 0; i < 4; i++ {
		ctx.Next()
	}
}

func (ctx *Shift128plusContext) Next() uint64 {
	x := ctx.v[0]
	y := ctx.v[1]
	ctx.v[0] = y
	x ^= x << 23
	x ^= y ^ (x >> 17) ^ (y >> 26)
	ctx.v[1] = x
	return x + y
}
