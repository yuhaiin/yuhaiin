// Package oauth holds the transport- and storage-independent parts of the
// Yuhaiin OAuth 2.1 Authorization Server: protected resource descriptions,
// protocol validation (PKCE, redirect URIs, scopes, resource indicators) and
// the standard error and metadata documents.
//
// It deliberately knows nothing about users, credentials or SQLite. The
// management identity runtime owns those and implements the Authorization
// Server on top of this package. Resource servers, including the MCP adapter,
// describe themselves with a Resource and never depend on the Authorization
// Server implementation.
package oauth

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

// Resource describes one protected resource (RFC 8707 / RFC 9728). Its
// canonical URI is the configured issuer origin followed by Path; it is never
// derived from the Host header or forwarding headers of a request.
type Resource struct {
	// ID is a short stable identifier, e.g. "api" or "mcp".
	ID string
	// Name is shown on the consent page and in resource metadata.
	Name string
	// Path is appended to the issuer to form the canonical resource URI. It
	// also names the RFC 9728 metadata document under
	// /.well-known/oauth-protected-resource.
	Path string
	// Prefixes lists the request paths this resource serves. A request path
	// equal to a prefix, or below a prefix ending in "/", belongs to it.
	Prefixes []string
	// Scopes are the OAuth scopes a client may request for this resource. Each
	// scope is a delegable management permission identifier.
	Scopes []permission.Permission
	// Required, when set, must be granted for any token of this resource to be
	// useful; the consent page presents it as mandatory.
	Required permission.Permission
	// LegacyCredentials lets sessions and API tokens authenticate to this
	// resource too. Resources without it accept only OAuth access tokens issued
	// for exactly this resource.
	LegacyCredentials bool
}

// URI returns the canonical resource identifier for issuer.
func (r Resource) URI(issuer string) string { return issuer + r.Path }

// MetadataPath is the RFC 9728 protected resource metadata path.
func (r Resource) MetadataPath() string { return "/.well-known/oauth-protected-resource" + r.Path }

// MetadataURL is the absolute RFC 9728 metadata URL for issuer.
func (r Resource) MetadataURL(issuer string) string { return issuer + r.MetadataPath() }

// Serves reports whether a request path belongs to the resource.
func (r Resource) Serves(path string) bool {
	for _, prefix := range r.Prefixes {
		if path == strings.TrimSuffix(prefix, "/") || strings.HasSuffix(prefix, "/") && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// AllowsScope reports whether scope may be requested for the resource.
func (r Resource) AllowsScope(scope permission.Permission) bool {
	return slices.Contains(r.Scopes, scope)
}

func (r Resource) validate() error {
	if !validIdentifier(r.ID) || r.Name == "" || !strings.HasPrefix(r.Path, "/") || strings.HasSuffix(r.Path, "/") || strings.ContainsAny(r.Path, "?#*") || len(r.Prefixes) == 0 || len(r.Scopes) == 0 {
		return fmt.Errorf("invalid OAuth resource %q", r.ID)
	}
	for _, scope := range r.Scopes {
		if !permission.Delegable(scope) {
			return fmt.Errorf("OAuth resource %q exposes non-delegable scope %q", r.ID, scope)
		}
	}
	if r.Required != "" && !r.AllowsScope(r.Required) {
		return fmt.Errorf("OAuth resource %q requires scope %q it does not expose", r.ID, r.Required)
	}
	for _, prefix := range r.Prefixes {
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("OAuth resource %q has invalid prefix %q", r.ID, prefix)
		}
	}
	return nil
}

func validIdentifier(id string) bool {
	return id != "" && len(id) <= 32 && only(id, "abcdefghijklmnopqrstuvwxyz0123456789-")
}

// Registry is the set of protected resources served by this process.
// Resources are registered at startup; the Authorization Server needs no
// change to serve a new one.
type Registry struct {
	mu        sync.RWMutex
	resources []Resource
}

// Register adds a resource. Identifiers, paths and request prefixes must be
// unique across resources.
func (r *Registry) Register(resource Resource) error {
	if err := resource.validate(); err != nil {
		return err
	}
	resource.Scopes = slices.Clone(resource.Scopes)
	resource.Prefixes = slices.Clone(resource.Prefixes)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.resources {
		if existing.ID == resource.ID || existing.Path == resource.Path {
			return fmt.Errorf("duplicate OAuth resource %q", resource.ID)
		}
		for _, prefix := range resource.Prefixes {
			if slices.Contains(existing.Prefixes, prefix) {
				return fmt.Errorf("OAuth resource %q overlaps %q at %q", resource.ID, existing.ID, prefix)
			}
		}
	}
	r.resources = append(r.resources, resource)
	return nil
}

// All returns the registered resources in registration order.
func (r *Registry) All() []Resource {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.resources)
}

// ByID returns the resource with the identifier id.
func (r *Registry) ByID(id string) (Resource, bool) {
	for _, resource := range r.All() {
		if resource.ID == id {
			return resource, true
		}
	}
	return Resource{}, false
}

// ForPath returns the resource that serves a request path.
func (r *Registry) ForPath(path string) (Resource, bool) {
	for _, resource := range r.All() {
		if resource.Serves(path) {
			return resource, true
		}
	}
	return Resource{}, false
}

// ForURI resolves a resource indicator (RFC 8707) against the issuer. The
// indicator must equal the canonical URI exactly after normalization.
func (r *Registry) ForURI(issuer, uri string) (Resource, bool) {
	canonical, err := CanonicalResource(uri)
	if err != nil {
		return Resource{}, false
	}
	for _, resource := range r.All() {
		if resource.URI(issuer) == canonical {
			return resource, true
		}
	}
	return Resource{}, false
}

// Scopes returns every scope exposed by any registered resource, in catalog order.
func (r *Registry) Scopes() []permission.Permission {
	var out []permission.Permission
	for _, p := range permission.DelegableValues() {
		for _, resource := range r.All() {
			if resource.AllowsScope(p) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}
