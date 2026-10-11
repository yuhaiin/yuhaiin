// Package otp implements the one-time password algorithms a VPN gateway needs
// for a second authentication factor: HOTP (RFC 4226) and the time-based TOTP
// (RFC 6238) built on it.
//
// These are the algorithms behind every authenticator app, and they are small
// enough that depending on something for them would cost more than it saves:
// HOTP is an HMAC, a truncation and a modulo. Both roles here use the same code
// — a client generates a code and a gateway verifies one — which is also why
// verification lives here rather than in a caller, since a correct verifier has
// to accept a window of counters and compare in constant time.
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"time"
)

// Algorithm selects the HMAC hash. SHA1 is the default every authenticator app
// assumes; the others exist because RFC 6238 defines them and some gateways use
// them. This is HMAC, so SHA1 here is not a collision-resistance claim.
type Algorithm int

const (
	SHA1 Algorithm = iota
	SHA256
	SHA512
)

func (a Algorithm) new() func() hash.Hash {
	switch a {
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

// String names the algorithm as an otpauth:// URI would.
func (a Algorithm) String() string {
	switch a {
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	default:
		return "SHA1"
	}
}

// DefaultPeriod and DefaultDigits are what authenticator apps assume when a
// secret does not say otherwise.
const (
	DefaultPeriod = 30 * time.Second
	DefaultDigits = 6
)

// Config parameters a TOTP secret. The zero value is the universal default:
// SHA1, 6 digits, a 30-second step.
type Config struct {
	Algorithm Algorithm
	Digits    int
	Period    time.Duration
	// Skew is how many steps either side of the current one a verifier accepts,
	// absorbing clock drift between the gateway and the user's phone. Zero means
	// one step either way, which is the usual allowance; set it explicitly to
	// widen or (with a negative value, via strict) to refuse any drift.
	Skew int
}

// digits treats only zero as "unset". A negative count is a caller's mistake and
// is passed through to fail validation rather than being silently defaulted.
func (c Config) digits() int {
	if c.Digits == 0 {
		return DefaultDigits
	}
	return c.Digits
}

func (c Config) period() time.Duration {
	if c.Period <= 0 {
		return DefaultPeriod
	}
	return c.Period
}

func (c Config) skew() int {
	if c.Skew == 0 {
		return 1
	}
	if c.Skew < 0 {
		return 0
	}
	return c.Skew
}

// pow10 is the modulus for each supported code length. A table rather than a
// loop because the digit count is small, fixed, and validated here.
var pow10 = [...]uint32{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

// HOTP computes the RFC 4226 code for one counter value.
func HOTP(secret []byte, counter uint64, cfg Config) (string, error) {
	digits := cfg.digits()
	if digits < 1 || digits >= len(pow10) {
		return "", fmt.Errorf("otp: %d digits is out of range", digits)
	}
	mac := hmac.New(cfg.Algorithm.new(), secret)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// RFC 4226 section 5.3 dynamic truncation: the low nibble of the last octet
	// selects a 4-octet window, whose top bit is cleared so the result is a
	// positive 31-bit integer regardless of the platform's signedness.
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, code%pow10[digits]), nil
}

// TOTP computes the RFC 6238 code for a moment in time.
func TOTP(secret []byte, t time.Time, cfg Config) (string, error) {
	return HOTP(secret, uint64(t.Unix()/int64(cfg.period().Seconds())), cfg)
}

// Verify reports whether code is valid for t, accepting the configured drift
// either side. The comparison is constant time: a code is a shared secret for
// its step, and leaking how much of a guess was right would let an attacker
// find it digit by digit.
func Verify(secret []byte, code string, t time.Time, cfg Config) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	step := int64(cfg.period().Seconds())
	counter := t.Unix() / step
	skew := cfg.skew()

	// Every candidate is checked even after one matches, so the work done does
	// not reveal which step was accepted.
	var ok int
	for i := -skew; i <= skew; i++ {
		c := counter + int64(i)
		if c < 0 {
			continue
		}
		want, err := HOTP(secret, uint64(c), cfg)
		if err != nil {
			return false
		}
		ok |= subtle.ConstantTimeCompare([]byte(want), []byte(code))
	}
	return ok == 1
}

// DecodeSecret decodes a base32 shared secret as authenticator apps present it:
// case-insensitive, with padding optional and spaces ignored, since users paste
// these out of QR-code screens that group them for readability.
func DecodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(s))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := enc.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("otp: %q is not a base32 secret: %w", s, err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("otp: secret is empty")
	}
	return key, nil
}
