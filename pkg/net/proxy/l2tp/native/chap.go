package native

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // RFC 2759 requires MD4 for the legacy NT password hash.
)

func (s *Session) handleCHAP(code, id byte, data []byte) error {
	p := s.pppState
	if p.auth != protoCHAP {
		return nil
	}
	switch code {
	case 1:
		if len(data) < 1 || data[0] == 0 || int(data[0])+1 > len(data) {
			return nil
		}
		challenge := data[1 : 1+int(data[0])]
		var response []byte
		if p.algorithm == 5 {
			response = challengeResponse(id, s.cfg.Password, challenge)
		} else {
			if len(challenge) != 16 {
				return errors.New("l2tp: invalid MS-CHAPv2 challenge")
			}
			var peer [16]byte
			_, _ = rand.Read(peer[:])
			var err error
			response, p.chapAuthenticator, err = mschapResponse(s.cfg.Username, s.cfg.Password, challenge, peer[:])
			if err != nil {
				return err
			}
		}
		p.chapID = id
		p.authStarted = true
		value := append([]byte{byte(len(response))}, response...)
		value = append(value, []byte(s.cfg.Username)...)
		return s.writePPP(protoCHAP, cp(2, id, value))
	case 3:
		if !p.authStarted || id != p.chapID {
			return nil
		}
		if p.algorithm == 0x81 && !bytes.HasPrefix(data, []byte(p.chapAuthenticator)) {
			return ErrAuth
		}
		p.authenticated = true
		s.mu.Lock()
		s.info.Auth = "chap-md5"
		if p.algorithm == 0x81 {
			s.info.Auth = "mschap-v2"
		}
		s.mu.Unlock()
	case 4:
		if p.authStarted && id == p.chapID {
			return ErrAuth
		}
	}
	return nil
}

// RFC 2759 uses UTF-16LE/MD4 password hashes and three DES challenge blocks.
// These legacy primitives are confined to PPP interoperability, not encryption.
func mschapResponse(username, password string, auth, peer []byte) ([]byte, string, error) {
	if len(auth) != 16 || len(peer) != 16 {
		return nil, "", errors.New("l2tp: invalid MS-CHAPv2 challenge size")
	}
	if _, user, ok := strings.Cut(username, "\\"); ok {
		username = user
	}
	passwordBytes := make([]byte, 0, len(password)*2)
	for _, v := range utf16.Encode([]rune(password)) {
		passwordBytes = append(passwordBytes, byte(v), byte(v>>8))
	}
	h := md4.New()
	h.Write(passwordBytes)
	passwordHash := h.Sum(nil)
	h.Reset()
	h.Write(passwordHash)
	passwordHashHash := h.Sum(nil)
	ch := sha1.New()
	ch.Write(peer)
	ch.Write(auth)
	ch.Write([]byte(username))
	challenge := ch.Sum(nil)[:8]
	padded := make([]byte, 21)
	copy(padded, passwordHash)
	nt := make([]byte, 24)
	for i := range 3 {
		b := padded[i*7 : i*7+7]
		key := [8]byte{b[0], b[0]<<7 | b[1]>>1, b[1]<<6 | b[2]>>2, b[2]<<5 | b[3]>>3, b[3]<<4 | b[4]>>4, b[4]<<3 | b[5]>>5, b[5]<<2 | b[6]>>6, b[6] << 1}
		for j := range key {
			key[j] &= 0xfe
		}
		cipher, err := des.NewCipher(key[:])
		if err != nil {
			return nil, "", err
		}
		cipher.Encrypt(nt[i*8:i*8+8], challenge)
	}
	response := make([]byte, 49)
	copy(response, peer)
	copy(response[24:], nt)
	ach := sha1.New()
	ach.Write(passwordHashHash)
	ach.Write(nt)
	ach.Write([]byte("Magic server to client signing constant"))
	digest := ach.Sum(nil)
	ach.Reset()
	ach.Write(digest)
	ach.Write(challenge)
	ach.Write([]byte("Pad to make it do more than one iteration"))
	return response, "S=" + strings.ToUpper(hex.EncodeToString(ach.Sum(nil))), nil
}
