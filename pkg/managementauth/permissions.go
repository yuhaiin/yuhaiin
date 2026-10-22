// Package managementauth owns local identities for the management HTTP API.
// Its identities and permissions are unrelated to network traffic identities.
package managementauth

import (
	"context"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/managementauth/permission"
)

type Permission = permission.Permission

const (
	NodesRead        = permission.NodesRead
	NodesWrite       = permission.NodesWrite
	InboundsRead     = permission.InboundsRead
	InboundsWrite    = permission.InboundsWrite
	RoutesRead       = permission.RoutesRead
	RoutesWrite      = permission.RoutesWrite
	ResolverRead     = permission.ResolverRead
	ResolverWrite    = permission.ResolverWrite
	ConnectionsRead  = permission.ConnectionsRead
	ConnectionsWrite = permission.ConnectionsWrite
	GatewayRead      = permission.GatewayRead
	GatewayWrite     = permission.GatewayWrite
	SettingsRead     = permission.SettingsRead
	SettingsWrite    = permission.SettingsWrite
	Diagnostics      = permission.Diagnostics
	BackupManage     = permission.BackupManage
	UpdateManage     = permission.UpdateManage
	UsersManage      = permission.UsersManage
	TokensManage     = permission.TokensManage
	SecurityRead     = permission.SecurityRead
	MetricsRead      = permission.MetricsRead
	IdentityRead     = permission.IdentityRead
	TokensOwn        = permission.TokensOwn
)

const (
	Admin    = "admin"
	ReadOnly = "read-only"
)

var allPermissions = permission.Values()

// RolePermissions returns a copy; callers cannot mutate the role registry.
// Configuration reads can contain upstream secrets. Read-only users therefore
// remain trusted operators, even though they cannot change configuration.
func RolePermissions(role string) []Permission {
	if role == Admin {
		return slices.Clone(allPermissions)
	}
	if role == ReadOnly {
		return []Permission{NodesRead, InboundsRead, RoutesRead, ResolverRead,
			ConnectionsRead, GatewayRead, SettingsRead, MetricsRead, IdentityRead, TokensOwn}
	}
	return nil
}

type Principal struct {
	UserID         string       `json:"userId"`
	CredentialType string       `json:"credentialType"`
	Permissions    []Permission `json:"permissions"`
}

func (p Principal) Allows(permission Permission) bool {
	return permission != "" && slices.Contains(p.Permissions, permission)
}

type principalKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
