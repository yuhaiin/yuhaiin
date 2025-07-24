package id

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
)

type IDGenerator struct {
	node atomic.Uint64
}

func (i *IDGenerator) Generate() (id uint64) {
	return i.node.Add(1)
}

type UUID [16]byte

func (uuid UUID) String() string {
	hextable := "0123456789abcdef"

	var dst = [36]byte{
		hextable[uuid[0]>>4], hextable[uuid[0]&0x0f],
		hextable[uuid[1]>>4], hextable[uuid[1]&0x0f],
		hextable[uuid[2]>>4], hextable[uuid[2]&0x0f],
		hextable[uuid[3]>>4], hextable[uuid[3]&0x0f],
		'-',
		hextable[uuid[4]>>4], hextable[uuid[4]&0x0f],
		hextable[uuid[5]>>4], hextable[uuid[5]&0x0f],
		'-',
		hextable[uuid[6]>>4], hextable[uuid[6]&0x0f],
		hextable[uuid[7]>>4], hextable[uuid[7]&0x0f],
		'-',
		hextable[uuid[8]>>4], hextable[uuid[8]&0x0f],
		hextable[uuid[9]>>4], hextable[uuid[9]&0x0f],
		'-',
		hextable[uuid[10]>>4], hextable[uuid[10]&0x0f],
		hextable[uuid[11]>>4], hextable[uuid[11]&0x0f],
		hextable[uuid[12]>>4], hextable[uuid[12]&0x0f],
		hextable[uuid[13]>>4], hextable[uuid[13]&0x0f],
		hextable[uuid[14]>>4], hextable[uuid[14]&0x0f],
		hextable[uuid[15]>>4], hextable[uuid[15]&0x0f],
	}

	return string(dst[:])
}

func (u UUID) HexString() string {
	return hex.EncodeToString(u[:])
}

func (u UUID) Bytes() []byte {
	return u[:]
}

func (u UUID) Base32() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(u[:])
}

func (u UUID) BigInt() *big.Int {
	return big.NewInt(0).SetBytes(u[:])
}

func GenerateUUID() UUID {
	var u UUID

	_, err := rand.Read(u[:])
	if err != nil {
		panic(err)
	}

	u[6] = (u[6] & 0x0f) | 0x40 // Version 4
	u[8] = (u[8] & 0x3f) | 0x80 // Variant is 10
	return u
}

func ParseUUID(s string) (UUID, error) {
	var uuid UUID
	switch len(s) {
	case 36 + 9, // urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
		36 + 2: // {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
		if s[0] == '{' {
			s = s[1:]
		} else {
			if !strings.EqualFold(s[:9], "urn:uuid:") {
				return uuid, fmt.Errorf("invalid urn prefix: %q", s[:9])
			}
			s = s[9:]
		}

		fallthrough

	// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	case 36:
		// s is now at least 36 bytes long
		// it must be of the form  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
		if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
			return uuid, errors.New("invalid UUID format")
		}

	// xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	case 32:
	default:
		return uuid, fmt.Errorf("invalid uuid length: %d", len(s))
	}

	s = strings.ReplaceAll(s, "-", "")

	data, err := hex.DecodeString(s)
	if err != nil {
		return uuid, err
	}
	return UUID(data), nil
}
