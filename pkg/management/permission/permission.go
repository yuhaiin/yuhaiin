// Package permission defines the stable permission identifiers shared by the
// management API and its authentication middleware.
package permission

import "slices"

// Permission is a permission identifier carried as a string in the HTTP API.
type Permission string

const (
	ConfigurationRead         Permission = "configuration:read"
	ConfigurationWrite        Permission = "configuration:write"
	ConfigurationRollback     Permission = "configuration:rollback"
	NodesRead                 Permission = "nodes:read"
	NodesWrite                Permission = "nodes:write"
	InboundsRead              Permission = "inbounds:read"
	InboundsWrite             Permission = "inbounds:write"
	TrafficAccessRead         Permission = "traffic-access:read"
	TrafficAccessWrite        Permission = "traffic-access:write"
	SecretsRead               Permission = "secrets:read"
	SecretsManage             Permission = "secrets:manage"
	SystemExecute             Permission = "system:execute"
	RolesRead                 Permission = "roles:read"
	RolesWrite                Permission = "roles:write"
	ResourceRead              Permission = "resources:read"
	ResourceWrite             Permission = "resources:write"
	RoutesRead                Permission = "routes:read"
	RoutesWrite               Permission = "routes:write"
	ResolverRead              Permission = "resolver:read"
	ResolverWrite             Permission = "resolver:write"
	ConnectionsRead           Permission = "connections:read"
	ConnectionsWrite          Permission = "connections:write"
	DNSHistoryRead            Permission = "dns-history:read"
	DNSHistoryWrite           Permission = "dns-history:write"
	GatewayRead               Permission = "gateway:read"
	CertificatesRead          Permission = "certificates:read"
	CertificatesManage        Permission = "certificates:manage"
	GatewayWrite              Permission = "gateway:write"
	SettingsRead              Permission = "settings:read"
	SettingsWrite             Permission = "settings:write"
	Diagnostics               Permission = "diagnostics:run"
	BackupManage              Permission = "backup:manage"
	UpdateManage              Permission = "update:manage"
	UsersManage               Permission = "users:manage"
	TokensManage              Permission = "tokens:manage"
	SecurityRead              Permission = "security:read"
	SecurityWrite             Permission = "security:write"
	SecurityExport            Permission = "security:export"
	MetricsRead               Permission = "metrics:read"
	IdentityRead              Permission = "identity:read"
	TokensOwn                 Permission = "tokens:own"
	ProxyCredentialsManage    Permission = "proxy-credentials:manage"
	UpstreamCredentialsManage Permission = "upstream-credentials:manage"
	ProxyCredentialsOwn       Permission = "proxy-credentials:own"
	UsageOwn                  Permission = "usage:own"
	UsageRead                 Permission = "usage:read"
	MCPConnect                Permission = "mcp:connect"
)

// Definition describes a permission in the management API catalog.
type Definition struct {
	ID          Permission `json:"id"`
	Category    string     `json:"category"`
	Description string     `json:"description"`
	// Delegable permissions may be granted to OAuth clients as scopes.
	Delegable bool `json:"delegable"`
}

type entry struct {
	ID          Permission
	Category    string
	Description string
}

var catalog = [...]entry{
	{ConfigurationRead, "security", "Inspect permission-filtered configuration stages, diffs and history."},
	{ConfigurationWrite, "security", "Stage, validate and commit configuration changes within resource permissions."},
	{ConfigurationRollback, "security", "Prepare configuration rollback within current resource permissions."},
	{SecurityExport, "security", "Export structured management security audit pages."},
	{SecurityWrite, "security", "Change management trust boundaries, identity providers and security audit settings."},
	{SecretsRead, "security", "Explicitly retrieve reusable configuration secrets, backups and raw diagnostic data."},
	{SecretsManage, "security", "Change inline configuration secrets and private keys."},
	{SystemExecute, "security", "Change executable hooks or native library configuration, and restore executable backups."},
	{RolesRead, "security", "Inspect custom management roles and effective permissions."},
	{RolesWrite, "security", "Manage permission-bounded custom roles and assignments."},
	{ResourceRead, "security", "Inspect identity resource policies and effective limits."},
	{ResourceWrite, "security", "Validate and activate identity resource policies."},
	{TrafficAccessRead, "security", "Inspect traffic access policies and preview effective authorization."},
	{TrafficAccessWrite, "security", "Validate and activate traffic access policies."},
	{CertificatesRead, "certificates", "View managed HTTPS certificates, renewal status and public DNS provider configuration."},
	{CertificatesManage, "certificates", "Manage HTTPS certificates, DNS credentials and certificate issuance."},
	{UsageOwn, "users", "View your own traffic usage and connection audit."},
	{UsageRead, "users", "View traffic usage and connection audits for all users."},
	{ProxyCredentialsOwn, "users", "Create, revoke, and rotate your own inbound proxy credentials."},
	{ProxyCredentialsManage, "users", "Manage user credentials for inbound proxy access."},
	{UpstreamCredentialsManage, "nodes", "Manage secrets used to authenticate outbound connections."},
	{NodesRead, "nodes", "View nodes, subscriptions, selectors, and publication status."},
	{NodesWrite, "nodes", "Create, update, select, and delete nodes or subscriptions."},
	{InboundsRead, "inbounds", "View inbound configuration and runtime status."},
	{InboundsWrite, "inbounds", "Create, update, retry, and delete inbounds."},
	{RoutesRead, "routes", "View route rules, lists, registries, and activation status."},
	{RoutesWrite, "routes", "Change routes, refresh lists, and update registries."},
	{ResolverRead, "resolver", "View resolver settings, hosts, cache, and query data."},
	{ResolverWrite, "resolver", "Change resolver settings, hosts, and cache."},
	{ConnectionsRead, "connections", "View connections, traffic, events, and history."},
	{ConnectionsWrite, "connections", "Close active connections."},
	{DNSHistoryRead, "connections", "View DNS query history, including queried domains, clients and processes."},
	{DNSHistoryWrite, "connections", "Clear DNS query history and change its recording and retention settings."},
	{GatewayRead, "gateway", "View gateway configuration, status, CA, and statistics."},
	{GatewayWrite, "gateway", "Change gateway settings, CA, filters, and statistics."},
	{SettingsRead, "settings", "View general settings, traffic controls, and interface details."},
	{SettingsWrite, "settings", "Change general settings and traffic controls."},
	{Diagnostics, "diagnostics", "Run diagnostics and view logs or profiling data."},
	{BackupManage, "backup", "Create and restore backups or change backup settings."},
	{UpdateManage, "update", "Check, install, inspect, and roll back software updates."},
	{UsersManage, "users", "Create, edit, disable, and manage user credentials."},
	{TokensManage, "tokens", "Manage API tokens belonging to other users."},
	{SecurityRead, "security", "View security events and authentication status."},
	{MetricsRead, "metrics", "Read process and service metrics."},
	{IdentityRead, "identity", "Read the current identity and manage its session."},
	{TokensOwn, "tokens", "Create, list, revoke, and rotate your own API tokens."},
	{MCPConnect, "integrations", "Connect Model Context Protocol (MCP) clients; each tool still requires its own permission."},
}

// Permissions that mint credentials, change identities or trust boundaries or
// run executables stay with sessions and API tokens. An OAuth client, which
// acts for a user through a consent screen, can never receive them.
// secrets:read is delegable, but only a resource that lists it (MCP, for raw
// logs) can grant it; the management API resource does not.
var interactiveOnly = [...]Permission{UsersManage, TokensManage, TokensOwn, RolesWrite, SecurityWrite, SystemExecute}

// Catalog returns a copy of every permission definition in stable order.
func Catalog() []Definition {
	out := make([]Definition, len(catalog))
	for i, e := range catalog {
		out[i] = Definition{ID: e.ID, Category: e.Category, Description: e.Description, Delegable: Delegable(e.ID)}
	}
	return out
}

// Delegable reports whether p may be granted to an OAuth client as a scope.
// The OAuth scope identifier is the permission identifier itself, so no second
// registry or mapping exists.
func Delegable(p Permission) bool {
	return slices.ContainsFunc(catalog[:], func(d entry) bool { return d.ID == p }) && !slices.Contains(interactiveOnly[:], p)
}

// DelegableValues returns every delegable permission in catalog order.
func DelegableValues() []Permission {
	out := make([]Permission, 0, len(catalog))
	for _, definition := range catalog {
		if Delegable(definition.ID) {
			out = append(out, definition.ID)
		}
	}
	return out
}

// Lookup returns the catalog definition of p.
func Lookup(p Permission) (Definition, bool) {
	for _, e := range catalog {
		if e.ID == p {
			return Definition{ID: e.ID, Category: e.Category, Description: e.Description, Delegable: Delegable(p)}, true
		}
	}
	return Definition{}, false
}

// Values returns the permission identifiers in the same order as Catalog.
func Values() []Permission {
	permissions := make([]Permission, len(catalog))
	for i, definition := range catalog {
		permissions[i] = definition.ID
	}
	return permissions
}
