package transport

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
)

func PeerPairID(key [32]byte) [16]byte {
	hash := sha256.Sum256(key[:])
	return [16]byte(hash[:16])
}

func PeerPairIDString(key [32]byte) string {
	id := PeerPairID(key)
	return hex.EncodeToString(id[:])
}

func DecodePeerKey(s string) ([32]byte, error) {
	var key [32]byte
	n, err := base64.StdEncoding.Decode(key[:], []byte(s))
	if err != nil || n != len(key) || key == [32]byte{} || len(s) != base64.StdEncoding.EncodedLen(len(key)) {
		return key, errors.New("expected a nonzero 32-byte base64 value")
	}
	return key, nil
}

func ValidatePeerCoordinator(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, " \t\r\n/") {
		return errors.New("peer tunnel: coordinator must be host:port")
	}
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 {
		return errors.New("peer tunnel: invalid coordinator port")
	}
	return nil
}
