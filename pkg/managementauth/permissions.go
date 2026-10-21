// Package managementauth owns local identities for the management HTTP API.
// Its identities and permissions are unrelated to network traffic identities.
package managementauth

import (
	"context"
	"slices"
)

type Permission string

const (
	NodesRead        Permission = "nodes:read"
	NodesWrite       Permission = "nodes:write"
	InboundsRead     Permission = "inbounds:read"
	InboundsWrite    Permission = "inbounds:write"
	RoutesRead       Permission = "routes:read"
	RoutesWrite      Permission = "routes:write"
	ResolverRead     Permission = "resolver:read"
	ResolverWrite    Permission = "resolver:write"
	ConnectionsRead  Permission = "connections:read"
	ConnectionsWrite Permission = "connections:write"
	GatewayRead      Permission = "gateway:read"
	GatewayWrite     Permission = "gateway:write"
	SettingsRead     Permission = "settings:read"
	SettingsWrite    Permission = "settings:write"
	Diagnostics      Permission = "diagnostics:run"
	BackupManage     Permission = "backup:manage"
	UpdateManage     Permission = "update:manage"
	UsersManage      Permission = "users:manage"
	TokensManage     Permission = "tokens:manage"
	SecurityRead     Permission = "security:read"
	MetricsRead      Permission = "metrics:read"
	IdentityRead     Permission = "identity:read"
	TokensOwn        Permission = "tokens:own"
)

const (
	Admin    = "admin"
	ReadOnly = "read-only"
)

var allPermissions = []Permission{
	NodesRead, NodesWrite, InboundsRead, InboundsWrite, RoutesRead, RoutesWrite,
	ResolverRead, ResolverWrite, ConnectionsRead, ConnectionsWrite, GatewayRead,
	GatewayWrite, SettingsRead, SettingsWrite, Diagnostics, BackupManage,
	UpdateManage, UsersManage, TokensManage, SecurityRead, MetricsRead, IdentityRead, TokensOwn,
}

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
