package user

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
)

type Usage string

const (
	UsageInbound  Usage = "inbound"
	UsageOutbound Usage = "outbound"
	UsageBoth     Usage = "both"
)

type CredentialType string

const (
	CredentialBasic CredentialType = "basic"
	CredentialUUID  CredentialType = "uuid"
	CredentialToken CredentialType = "token"
)

type Origin string

const (
	OriginManual   Origin = "manual"
	OriginMigrated Origin = "migrated"
)

type User struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Enabled    bool       `json:"enabled"`
	Origin     Origin     `json:"origin"`
	Usage      Usage      `json:"usage"`
	Credential Credential `json:"credential"`
}

type Credential struct {
	Type  CredentialType   `json:"type"`
	Basic *BasicCredential `json:"basic,omitzero"`
	UUID  *UUIDCredential  `json:"uuid,omitzero"`
	Token *TokenCredential `json:"token,omitzero"`
}

type BasicCredential struct {
	Username         *string `json:"username,omitzero"`
	Password         *string `json:"password,omitzero"`
	AllowAnyUsername bool    `json:"allowAnyUsername,omitzero"`
	AllowAnyPassword bool    `json:"allowAnyPassword,omitzero"`
}

type UUIDCredential struct {
	UUID string `json:"uuid"`
}

type TokenCredential struct {
	Token string `json:"token"`
}

type UserWrite struct {
	Name       string     `json:"name"`
	Enabled    bool       `json:"enabled"`
	Origin     Origin     `json:"origin,omitzero"`
	Usage      Usage      `json:"usage"`
	Credential Credential `json:"credential"`
}

type UserView struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Enabled            bool           `json:"enabled"`
	Origin             Origin         `json:"origin"`
	Usage              Usage          `json:"usage"`
	Credential         CredentialView `json:"credential"`
	OutboundReferences int            `json:"outboundReferences,omitzero"`
}

type CredentialView struct {
	Type        CredentialType `json:"type"`
	Username    string         `json:"username,omitzero"`
	HasUsername bool           `json:"hasUsername,omitzero"`
	HasSecret   bool           `json:"hasSecret"`
}

func (u User) Validate() error {
	if strings.TrimSpace(u.ID) == "" {
		return errors.New("user id is empty")
	}
	if err := ValidateUsage(u.Usage); err != nil {
		return err
	}
	if u.Origin == "" {
		u.Origin = OriginManual
	}
	if err := ValidateOrigin(u.Origin); err != nil {
		return err
	}
	return u.Credential.Validate()
}

func (w UserWrite) Validate() error {
	if err := ValidateUsage(w.Usage); err != nil {
		return err
	}
	origin := w.Origin
	if origin == "" {
		origin = OriginManual
	}
	if err := ValidateOrigin(origin); err != nil {
		return err
	}
	return w.Credential.Validate()
}

func (c Credential) Validate() error {
	count := 0
	if c.Basic != nil {
		count++
	}
	if c.UUID != nil {
		count++
	}
	if c.Token != nil {
		count++
	}
	if count != 1 {
		return errors.New("credential must contain exactly one variant")
	}
	switch c.Type {
	case CredentialBasic:
		if c.Basic == nil {
			return errors.New("basic credential is missing")
		}
		if c.Basic.Username == nil && c.Basic.Password == nil && !c.Basic.AllowAnyUsername && !c.Basic.AllowAnyPassword {
			return errors.New("basic credential has no usable field")
		}
	case CredentialUUID:
		if c.UUID == nil {
			return errors.New("uuid credential is missing")
		}
		if _, err := id.ParseUUID(c.UUID.UUID); err != nil {
			return fmt.Errorf("invalid uuid credential: %w", err)
		}
	case CredentialToken:
		if c.Token == nil || c.Token.Token == "" {
			return errors.New("token credential is empty")
		}
	default:
		return fmt.Errorf("unknown credential type %q", c.Type)
	}
	return nil
}

func ValidateUsage(value Usage) error {
	switch value {
	case UsageInbound, UsageOutbound, UsageBoth:
		return nil
	default:
		return fmt.Errorf("invalid user usage %q", value)
	}
}

func ValidateOrigin(value Origin) error {
	switch value {
	case OriginManual, OriginMigrated:
		return nil
	default:
		return fmt.Errorf("invalid user origin %q", value)
	}
}

func (u User) View() UserView {
	view := UserView{ID: u.ID, Name: u.Name, Enabled: u.Enabled, Origin: u.Origin, Usage: u.Usage}
	view.Credential.Type = u.Credential.Type
	switch u.Credential.Type {
	case CredentialBasic:
		if c := u.Credential.Basic; c != nil {
			if c.Username != nil {
				view.Credential.Username = *c.Username
				view.Credential.HasUsername = true
			}
			view.Credential.HasSecret = c.Password != nil
		}
	case CredentialUUID:
		view.Credential.HasSecret = u.Credential.UUID != nil && u.Credential.UUID.UUID != ""
	case CredentialToken:
		view.Credential.HasSecret = u.Credential.Token != nil && u.Credential.Token.Token != ""
	}
	return view
}

func String(value string) *string { return &value }
