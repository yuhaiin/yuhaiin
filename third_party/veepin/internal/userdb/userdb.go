// Package userdb reads the file of credentials a password-authenticating server
// accepts, and verifies one against it.
//
// Every password protocol in this tree already takes a Users map and looks the
// username up in it — the multi-user server was written, tested and
// interop-verified. What was missing was any way to say more than one pair on
// the way in, because the option surface could express only -user and -pass. So
// each facade collapsed the map to a single entry and veepin's password
// protocols served exactly one person, with no way to say otherwise short of a
// second listener on a second port. For the SSL-VPN protocols that is the
// entire deployment model those protocols exist for.
//
// The file is deliberately a file rather than an inline option. wireguard's
// OptServerPeers is the precedent for a repeated entity in this option surface,
// and it is the precedent for the plumbing rather than the format: credentials
// want the opposite of an inline value, because the point of keeping secrets
// out of the option map is defeated by putting several of them in it.
//
// # Format
//
//	# comments and blank lines are ignored
//	alice:hunter2
//	bob:$2a$12$Nt3s0Vk5r5Yy1ZfE9nQe8u6mQ0oPq7wXjK2sL1dR4tB8vC3nM5xGa
//
// The username is everything before the first colon, trimmed. The secret is
// everything after it, verbatim: a password ending in a space is a password,
// not a typo, and trimming it here would produce a login that fails with no
// explanation anywhere. Only a trailing CR is removed, so a file written on
// Windows works.
//
// # Which protocols can hold a hash
//
// The two classes below are the whole of it, and they follow from the
// protocol rather than from a preference. A protocol that receives the
// password and compares it can compare against a bcrypt verifier instead, so
// the server never stores the password at all. A protocol that computes its
// response FROM the password — MS-CHAPv2, and SoftEther's challenge — cannot:
// there is nothing to compare, and a hash is not a substitute for the input to
// a derivation. doc/security.md carries the table; this package enforces it, so
// an operator who puts a hash in an MS-CHAPv2 file is told at startup rather
// than discovering it as a login that never succeeds.
package userdb

import (
	"crypto/subtle"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Class says whether a protocol can verify a hashed secret. It is a property of
// the protocol's authentication exchange, not a configuration choice.
type Class int

const (
	// Verifiable: the protocol receives the password and compares it, so the
	// file may hold either a password or a bcrypt verifier. AnyConnect,
	// Fortinet, GlobalProtect, Ivanti, Cisco XAuth and SSH password auth.
	Verifiable Class = iota
	// NeedsPlaintext: the protocol computes its response FROM the password, so
	// the server must hold the password itself. SSTP and L2TP/IPsec, both
	// MS-CHAPv2.
	NeedsPlaintext
)

// bcryptPrefixes are the verifier spellings this package recognises. They are
// also what htpasswd -B and every other bcrypt tool emit, which is the point:
// an operator generating a verifier should not need a veepin-specific tool.
var bcryptPrefixes = []string{"$2a$", "$2b$", "$2y$"}

// IsHash reports whether a stored secret is a verifier rather than a password.
func IsHash(stored string) bool {
	for _, p := range bcryptPrefixes {
		if strings.HasPrefix(stored, p) {
			return true
		}
	}
	return false
}

// Verify reports whether offered is the password behind stored, which is either
// a bcrypt verifier or the password itself.
//
// Both branches are constant-time with respect to the password: bcrypt's
// comparison is by construction, and the plaintext branch goes through
// subtle.ConstantTimeCompare so a wrong password cannot be distinguished from a
// wrong one of a different length by timing. Two of the engines this replaces
// used a bare == , which leaked exactly that.
func Verify(stored, offered string) bool {
	if IsHash(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(offered)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(offered)) == 1
}

// Hash returns a bcrypt verifier for password, at the library's default cost.
//
// bcrypt ignores everything past the 72nd byte of its input, so a longer
// password is refused here rather than silently truncated to one that a
// different, shorter password also satisfies.
func Hash(password string) (string, error) {
	if len(password) > 72 {
		return "", fmt.Errorf("userdb: bcrypt ignores everything past 72 bytes and this password is %d; "+
			"a verifier for it would also accept its first 72 bytes", len(password))
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("userdb: hash: %w", err)
	}
	return string(h), nil
}

// Parse reads username:secret lines. origin names the source in errors — a path
// for Load, or a description for a caller that already has the bytes.
func Parse(data []byte, class Class, origin string) (map[string]string, error) {
	users := map[string]string{}
	lineno := 0
	for raw := range strings.SplitSeq(string(data), "\n") {
		lineno++
		line := strings.TrimSuffix(raw, "\r")
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		name, secret, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("userdb: %s:%d: no colon; each line is username:secret", origin, lineno)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("userdb: %s:%d: empty username", origin, lineno)
		}
		if secret == "" {
			return nil, fmt.Errorf("userdb: %s:%d: %q has an empty secret", origin, lineno, name)
		}
		if _, dup := users[name]; dup {
			// Not last-wins: which of the two the operator meant is unknowable,
			// and picking one silently is how a revoked password stays live.
			return nil, fmt.Errorf("userdb: %s:%d: %q appears twice", origin, lineno, name)
		}
		if class == NeedsPlaintext && IsHash(secret) {
			return nil, fmt.Errorf("userdb: %s:%d: %q holds a bcrypt verifier, but this protocol "+
				"computes its response from the password (MS-CHAPv2) and cannot verify a hash; "+
				"store the password itself, and see doc/security.md", origin, lineno, name)
		}
		users[name] = secret
	}
	return users, nil
}

// Load reads and parses a credentials file.
func Load(path string, class Class) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("userdb: %w", err)
	}
	return Parse(data, class, path)
}

// Resolve builds the Users map a server facade hands its engine, from the file
// and the single-pair shorthand together.
//
// Both are first-class. -user/-pass is what every runbook and every interop
// cell passes and stays exactly as it was; the file is what makes the server
// serve more than one person. Where a name is in both, the command line wins:
// it is the more specific and more recent statement, and an operator overriding
// one entry for a moment should not have to edit the file.
func Resolve(class Class, path, user, pass string) (map[string]string, error) {
	users := map[string]string{}
	if path != "" {
		loaded, err := Load(path, class)
		if err != nil {
			return nil, err
		}
		users = loaded
	}
	if user != "" {
		users[user] = pass
	}
	return users, nil
}
