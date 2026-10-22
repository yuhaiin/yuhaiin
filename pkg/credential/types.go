// Package credential defines outbound secrets independently of local users.
package credential

import "context"

const (
	Password         = "password"
	UsernamePassword = "username-password"
)

type Metadata struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Revision int64  `json:"revision"`
}

// Value is internal resolution material. Management lists return Metadata only.
type Value struct {
	Type     string `json:"type"`
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
}

type Resolver interface {
	Lookup(context.Context, string) (Value, int64, error)
}
