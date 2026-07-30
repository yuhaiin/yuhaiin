package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	contractuser "github.com/Asutorufa/yuhaiin/pkg/contract/user"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

var (
	ErrNotFound = errors.New("authentication credential not found")
	ErrDisabled = errors.New("authentication user is disabled")
	ErrType     = errors.New("authentication credential type mismatch")
	ErrRequired = errors.New("authentication credential is required")
)

type Principal struct{ UserID string }

type BasicAuthenticator interface {
	AuthBasic(string, string) (Principal, error)
}

type UsernameAuthenticator interface {
	AuthUsername(string) (Principal, error)
}

type PasswordAuthenticator interface {
	AuthPassword(string) (Principal, error)
}

type ResolvedCredential struct {
	UserID   string
	Username string
	Password string
	UUID     string
	Token    string
}

type Snapshot struct {
	Users map[string]contractuser.User
	Order []string
}

type Center struct {
	store *plainstore.UserStore
	cache atomic.Pointer[Snapshot]
}

func NewCenter(store *plainstore.UserStore) (*Center, error) {
	center := &Center{store: store}
	if err := center.Reload(context.Background()); err != nil {
		return nil, err
	}
	return center, nil
}

func (c *Center) Reload(ctx context.Context) error {
	if c == nil || c.store == nil {
		return errors.New("auth center user store is nil")
	}
	users, err := c.store.ListUsers(ctx)
	if err != nil {
		return err
	}
	snapshot := &Snapshot{Users: make(map[string]contractuser.User, len(users)), Order: make([]string, 0, len(users))}
	for _, user := range users {
		snapshot.Users[user.ID] = user
		snapshot.Order = append(snapshot.Order, user.ID)
	}
	sort.Strings(snapshot.Order)
	c.cache.Store(snapshot)
	return nil
}

func (c *Center) AuthBasic(username, password string) (Principal, error) {
	return c.match(func(user contractuser.User) bool {
		if user.Credential.Type != contractuser.CredentialBasic || user.Credential.Basic == nil {
			return false
		}
		basic := user.Credential.Basic
		return matchField(username, basic.Username, basic.AllowAnyUsername) && matchField(password, basic.Password, basic.AllowAnyPassword) && (basic.Username != nil || basic.AllowAnyUsername) && (basic.Password != nil || basic.AllowAnyPassword)
	})
}

func (c *Center) AuthUsername(username string) (Principal, error) {
	return c.match(func(user contractuser.User) bool {
		if user.Credential.Type != contractuser.CredentialBasic || user.Credential.Basic == nil {
			return false
		}
		basic := user.Credential.Basic
		return (basic.Username != nil || basic.AllowAnyUsername) && matchField(username, basic.Username, basic.AllowAnyUsername)
	})
}

func (c *Center) AuthPassword(password string) (Principal, error) {
	return c.match(func(user contractuser.User) bool {
		if user.Credential.Type != contractuser.CredentialBasic || user.Credential.Basic == nil {
			return false
		}
		basic := user.Credential.Basic
		return (basic.Password != nil || basic.AllowAnyPassword) && matchField(password, basic.Password, basic.AllowAnyPassword)
	})
}

func (c *Center) ResolveCredential(userID, protocolType string) (ResolvedCredential, error) {
	user, err := c.user(userID)
	if err != nil {
		return ResolvedCredential{}, err
	}
	if !user.Enabled {
		return ResolvedCredential{}, fmt.Errorf("%w: %s", ErrDisabled, userID)
	}
	if user.Usage != contractuser.UsageOutbound && user.Usage != contractuser.UsageBoth {
		return ResolvedCredential{}, fmt.Errorf("%w: user %s is not outbound-enabled", ErrType, userID)
	}
	result := ResolvedCredential{UserID: userID}
	switch protocolType {
	case "vmess", "vless":
		if user.Credential.Type != contractuser.CredentialUUID || user.Credential.UUID == nil {
			return result, fmt.Errorf("%w: %s", ErrType, userID)
		}
		result.UUID = user.Credential.UUID.UUID
	case "tailscale":
		if user.Credential.Type != contractuser.CredentialToken || user.Credential.Token == nil {
			return result, fmt.Errorf("%w: %s", ErrType, userID)
		}
		result.Token = user.Credential.Token.Token
	case "shadowsocks", "shadowsocksr", "trojan", "yuubinsya", "aead":
		if user.Credential.Type != contractuser.CredentialBasic || user.Credential.Basic == nil || user.Credential.Basic.Password == nil {
			return result, fmt.Errorf("%w: %s", ErrRequired, userID)
		}
		result.Password = *user.Credential.Basic.Password
	case "http", "socks5":
		if user.Credential.Type != contractuser.CredentialBasic || user.Credential.Basic == nil || user.Credential.Basic.Username == nil || user.Credential.Basic.Password == nil {
			return result, fmt.Errorf("%w: %s", ErrRequired, userID)
		}
		result.Username = *user.Credential.Basic.Username
		result.Password = *user.Credential.Basic.Password
	default:
		return result, fmt.Errorf("unsupported credential protocol %q", protocolType)
	}
	return result, nil
}

func (c *Center) user(userID string) (contractuser.User, error) {
	snapshot := c.cache.Load()
	if snapshot == nil {
		return contractuser.User{}, errors.New("auth center snapshot is unavailable")
	}
	user, ok := snapshot.Users[userID]
	if !ok {
		return contractuser.User{}, fmt.Errorf("%w: %s", ErrNotFound, userID)
	}
	return user, nil
}

func (c *Center) match(predicate func(contractuser.User) bool) (Principal, error) {
	snapshot := c.cache.Load()
	if snapshot == nil {
		return Principal{}, errors.New("auth center snapshot is unavailable")
	}
	for _, userID := range snapshot.Order {
		user := snapshot.Users[userID]
		if !user.Enabled || (user.Usage != contractuser.UsageInbound && user.Usage != contractuser.UsageBoth) {
			continue
		}
		if predicate(user) {
			return Principal{UserID: user.ID}, nil
		}
	}
	return Principal{}, ErrNotFound
}

func matchField(value string, expected *string, allowAny bool) bool {
	if allowAny {
		return true
	}
	if expected == nil {
		return false
	}
	if len(value) != len(*expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(value), []byte(*expected)) == 1
}

func (c *Center) Store() *plainstore.UserStore { return c.store }

// HasBasicUsers reports whether a protocol using username/password
// authentication should enable the central authenticator. A nil authenticator
// deliberately preserves the protocol's no-auth behavior when no inbound user
// has been configured.
func (c *Center) HasBasicUsers() bool {
	return c.hasInbound(func(user contractuser.User) bool {
		basic := user.Credential.Basic
		return user.Credential.Type == contractuser.CredentialBasic && basic != nil &&
			(basic.Username != nil || basic.AllowAnyUsername) &&
			(basic.Password != nil || basic.AllowAnyPassword)
	})
}

func (c *Center) HasUsernameUsers() bool {
	return c.hasInbound(func(user contractuser.User) bool {
		basic := user.Credential.Basic
		return user.Credential.Type == contractuser.CredentialBasic && basic != nil && (basic.Username != nil || basic.AllowAnyUsername)
	})
}

func (c *Center) HasPasswordUsers() bool {
	return c.hasInbound(func(user contractuser.User) bool {
		basic := user.Credential.Basic
		return user.Credential.Type == contractuser.CredentialBasic && basic != nil && (basic.Password != nil || basic.AllowAnyPassword)
	})
}

// InboundPasswords is consumed only by protocols whose wire handshake needs
// the secret itself (for example Yuubinsya and the encrypted transport). The
// central store remains the source of truth; callers must not persist the
// returned values.
func (c *Center) InboundPasswords() []string {
	if c == nil || c.cache.Load() == nil {
		return nil
	}
	var passwords []string
	snapshot := c.cache.Load()
	for _, userID := range snapshot.Order {
		user := snapshot.Users[userID]
		if !user.Enabled || (user.Usage != contractuser.UsageInbound && user.Usage != contractuser.UsageBoth) || user.Credential.Type != contractuser.CredentialBasic || user.Credential.Basic == nil || user.Credential.Basic.Password == nil {
			continue
		}
		passwords = append(passwords, *user.Credential.Basic.Password)
	}
	return passwords
}

func (c *Center) hasInbound(predicate func(contractuser.User) bool) bool {
	if c == nil || c.cache.Load() == nil {
		return false
	}
	snapshot := c.cache.Load()
	for _, userID := range snapshot.Order {
		user := snapshot.Users[userID]
		if user.Enabled && (user.Usage == contractuser.UsageInbound || user.Usage == contractuser.UsageBoth) && predicate(user) {
			return true
		}
	}
	return false
}

func (c *Center) UserView(ctx context.Context, userID string) (contractuser.UserView, error) {
	user, err := c.store.Get(ctx, userID)
	if err != nil {
		return contractuser.UserView{}, err
	}
	return user.View(), nil
}

func NormalizeProtocolType(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
