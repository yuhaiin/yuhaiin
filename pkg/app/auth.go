package app

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
)

const legacyAuthIterations = 600_000

// Auth is the process-local Basic verifier for embedded HandleFunc callers.
// Construct it with NewAuth; manually populated SHA-256 values are not accepted.
// The server executable uses the separate management identity middleware.
type Auth struct {
	Username [32]byte
	Password [32]byte

	salt              [16]byte
	verificationSlots chan struct{}
}

func NewAuth(username, password string) *Auth {
	a := &Auth{Username: sha256.Sum256([]byte(username))}
	rand.Read(a.salt[:])
	key, err := pbkdf2.Key(sha256.New, password, a.salt[:], legacyAuthIterations, len(a.Password))
	if err != nil {
		// Only the fixed internal KDF parameters can fail. Never include input.
		panic("app: invalid legacy authentication KDF parameters")
	}
	copy(a.Password[:], key)
	a.verificationSlots = make(chan struct{}, 2)
	return a
}

func (a *Auth) Auth(password, username string) bool {
	return a.authenticate(context.Background(), password, username)
}

func (a *Auth) authenticate(ctx context.Context, password, username string) bool {
	if a == nil || a.verificationSlots == nil || ctx.Err() != nil {
		return false
	}
	// Request handlers wait without starting extra workers. Cancellation stops
	// queued work; at most two in-progress derivations finish before observing it.
	select {
	case a.verificationSlots <- struct{}{}:
		defer func() { <-a.verificationSlots }()
	case <-ctx.Done():
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	user := sha256.Sum256([]byte(username))
	key, err := pbkdf2.Key(sha256.New, password, a.salt[:], legacyAuthIterations, len(a.Password))
	if err != nil || ctx.Err() != nil {
		return false
	}
	validUser := subtle.ConstantTimeCompare(user[:], a.Username[:])
	validPassword := subtle.ConstantTimeCompare(key, a.Password[:])
	return validUser&validPassword == 1
}
