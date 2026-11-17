package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

// Secret prefixes make credential types distinguishable before any lookup. A
// management API token ("yu_") can never be mistaken for an OAuth token and
// vice versa, even though both travel as Bearer credentials.
const (
	AccessTokenPrefix       = "yuat_"
	RefreshTokenPrefix      = "yurt_"
	AuthorizationCodePrefix = "yuac_"
	ClientSecretPrefix      = "yucs_"
	ClientIDPrefix          = "yuc_"
)

// secretLength is the prefix plus 43 base64url characters (256 bits).
const secretBody = 43

// NewSecret returns prefix followed by 256 bits of cryptographically secure randomness.
func NewSecret(prefix string) string {
	var entropy [32]byte
	_, _ = rand.Read(entropy[:])
	return prefix + base64.RawURLEncoding.EncodeToString(entropy[:])
}

// NewClientID returns a random public client identifier.
func NewClientID() string {
	var entropy [16]byte
	_, _ = rand.Read(entropy[:])
	return ClientIDPrefix + base64.RawURLEncoding.EncodeToString(entropy[:])
}

// WellFormedSecret reports whether s has the given prefix and the exact length
// and alphabet of NewSecret output.
func WellFormedSecret(s, prefix string) bool {
	body, ok := strings.CutPrefix(s, prefix)
	if !ok || len(body) != secretBody {
		return false
	}
	return only(body, base64URLAlphabet)
}

const (
	base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	verifierAlphabet  = base64URLAlphabet + ".~"
	schemeAlphabet    = "abcdefghijklmnopqrstuvwxyz0123456789+.-"
)

// only reports whether every character of s is in alphabet.
func only(s, alphabet string) bool {
	for _, c := range s {
		if !strings.ContainsRune(alphabet, c) {
			return false
		}
	}
	return true
}

// Hash is the only form in which secrets, codes and tokens are persisted.
// They carry 256 bits of entropy, so an unsalted SHA-256 is a sufficient verifier.
func Hash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Error is an RFC 6749 section 5.2 error response.
type Error struct {
	Status      int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

func newError(status int, code, description string) *Error {
	return &Error{Status: status, Code: code, Description: description}
}

func InvalidRequest(description string) *Error {
	return newError(http.StatusBadRequest, "invalid_request", description)
}
func InvalidClient(description string) *Error {
	return newError(http.StatusUnauthorized, "invalid_client", description)
}
func InvalidGrant(description string) *Error {
	return newError(http.StatusBadRequest, "invalid_grant", description)
}
func UnauthorizedClient(description string) *Error {
	return newError(http.StatusBadRequest, "unauthorized_client", description)
}
func UnsupportedGrantType(description string) *Error {
	return newError(http.StatusBadRequest, "unsupported_grant_type", description)
}
func InvalidScope(description string) *Error {
	return newError(http.StatusBadRequest, "invalid_scope", description)
}
func InvalidTarget(description string) *Error {
	return newError(http.StatusBadRequest, "invalid_target", description)
}
func AccessDenied(description string) *Error {
	return newError(http.StatusForbidden, "access_denied", description)
}
func ServerError(description string) *Error {
	return newError(http.StatusInternalServerError, "server_error", description)
}
func InvalidRedirectURI(description string) *Error {
	return newError(http.StatusBadRequest, "invalid_redirect_uri", description)
}
func InvalidClientMetadata(description string) *Error {
	return newError(http.StatusBadRequest, "invalid_client_metadata", description)
}

// WriteError writes err as an OAuth JSON error. Non-OAuth errors become
// server_error without exposing their text.
func WriteError(w http.ResponseWriter, err error) {
	var oauthErr *Error
	if !errors.As(err, &oauthErr) {
		oauthErr = ServerError("")
	}
	if oauthErr.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
	}
	WriteJSON(w, oauthErr.Status, oauthErr)
}

// WriteJSON writes an uncacheable JSON response.
func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, value)
}

// ParseScope splits a space-delimited scope parameter. Unknown, duplicated or
// non-delegable scopes are rejected.
func ParseScope(raw string) ([]permission.Permission, error) {
	if len(raw) > 4096 {
		return nil, InvalidScope("scope is too long")
	}
	var out []permission.Permission
	for field := range strings.FieldsSeq(raw) {
		scope := permission.Permission(field)
		if !permission.Delegable(scope) {
			return nil, InvalidScope(fmt.Sprintf("unknown scope %q", field))
		}
		if !slices.Contains(out, scope) {
			out = append(out, scope)
		}
	}
	return out, nil
}

// FormatScope joins scopes in the canonical space-delimited form.
func FormatScope(scopes []permission.Permission) string {
	parts := make([]string, len(scopes))
	for i, scope := range scopes {
		parts[i] = string(scope)
	}
	return strings.Join(parts, " ")
}

// Intersect returns the members of a that also appear in every other list,
// preserving the order of a.
func Intersect(a []permission.Permission, others ...[]permission.Permission) []permission.Permission {
	out := make([]permission.Permission, 0, len(a))
	for _, p := range a {
		keep := !slices.Contains(out, p)
		for _, other := range others {
			keep = keep && slices.Contains(other, p)
		}
		if keep {
			out = append(out, p)
		}
	}
	return out
}

// Subset reports whether every member of a is in b.
func Subset(a, b []permission.Permission) bool {
	for _, p := range a {
		if !slices.Contains(b, p) {
			return false
		}
	}
	return true
}

// ValidCodeChallenge checks an RFC 7636 S256 code challenge: the base64url
// encoding of a SHA-256 digest, 43 characters without padding.
func ValidCodeChallenge(challenge string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(challenge) == 43 && len(decoded) == sha256.Size
}

// ValidCodeVerifier checks the RFC 7636 verifier alphabet and length.
func ValidCodeVerifier(verifier string) bool {
	return len(verifier) >= 43 && len(verifier) <= 128 && only(verifier, verifierAlphabet)
}

// VerifyPKCE checks verifier against an S256 challenge in constant time.
// The plain method is never supported.
func VerifyPKCE(verifier, challenge string) bool {
	if !ValidCodeVerifier(verifier) || !ValidCodeChallenge(challenge) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// S256Challenge derives the S256 challenge for verifier (used by tests and clients).
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NormalizeIssuer validates an operator-configured issuer. It must be an
// absolute https origin (or http on a loopback host for local use) with no
// path, query, fragment or user information, as RFC 8414 and the MCP
// authorization specification require.
func NormalizeIssuer(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("issuer must be an origin such as https://yuhaiin.example.com")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	switch u.Scheme {
	case "https":
	case "http":
		if !loopbackHost(u.Hostname()) {
			return "", errors.New("issuer must use https unless it is a loopback address")
		}
	default:
		return "", errors.New("issuer must use https")
	}
	if strings.ContainsAny(u.Host, "*") {
		return "", errors.New("issuer must not contain wildcards")
	}
	return u.Scheme + "://" + u.Host, nil
}

// CanonicalResource normalizes a resource indicator: absolute, no fragment,
// lowercase scheme and host, no trailing slash.
func CanonicalResource(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || u.User != nil || u.RawQuery != "" {
		return "", InvalidTarget("resource must be an absolute URI without a fragment or query")
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.TrimSuffix(u.EscapedPath(), "/"), nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

// Schemes that can execute script, read local data or otherwise abuse a
// browser redirect. Private-use schemes for native apps are otherwise allowed
// for public clients (RFC 8252 section 7.1).
var forbiddenSchemes = []string{"javascript", "data", "file", "vbscript", "about", "blob", "filesystem", "view-source", "ftp", "ws", "wss", "mailto", "tel", "sms", "chrome", "chrome-extension", "intent", "jar"}

// ValidateRedirectURI checks one registered redirect URI. Wildcards are never
// allowed. HTTPS is always permitted, HTTP only on loopback hosts, and
// private-use URI schemes only for public (native) clients.
func ValidateRedirectURI(raw string, public bool) error {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "* \t\r\n") {
		return InvalidRedirectURI("redirect URI is empty, too long or contains wildcards or whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Fragment != "" || strings.Contains(raw, "#") || u.User != nil {
		return InvalidRedirectURI("redirect URI must be absolute without a fragment or user information")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
		if u.Host == "" || u.Hostname() == "" {
			return InvalidRedirectURI("https redirect URI requires a host")
		}
	case "http":
		if !loopbackHost(u.Hostname()) {
			return InvalidRedirectURI("http redirect URIs are only allowed on loopback hosts")
		}
	default:
		if !public {
			return InvalidRedirectURI("confidential clients must use https redirect URIs")
		}
		if slices.Contains(forbiddenSchemes, scheme) {
			return InvalidRedirectURI("redirect URI scheme is not allowed")
		}
		if !only(scheme, schemeAlphabet) {
			return InvalidRedirectURI("redirect URI scheme is invalid")
		}
	}
	return nil
}

// MatchRedirectURI compares a requested redirect URI with a registered one.
// The comparison is exact, except that the port of a loopback IP literal may
// differ, because native apps bind an ephemeral port (RFC 8252 section 7.3).
func MatchRedirectURI(registered, requested string) bool {
	if registered == requested {
		return true
	}
	r, err1 := url.Parse(registered)
	q, err2 := url.Parse(requested)
	if err1 != nil || err2 != nil || r.Scheme != "http" || q.Scheme != "http" {
		return false
	}
	addr, err := netip.ParseAddr(r.Hostname())
	return err == nil && addr.Unmap().IsLoopback() && r.Hostname() == q.Hostname() && r.EscapedPath() == q.EscapedPath() && r.RawQuery == q.RawQuery && q.Fragment == "" && q.User == nil
}

// RedirectOrigin is the scheme and host shown on the consent page.
func RedirectOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Host == "" {
		return u.Scheme + ":"
	}
	return u.Scheme + "://" + u.Host
}

// AuthorizationServerMetadata is the RFC 8414 document.
type AuthorizationServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

// ProtectedResourceMetadata is the RFC 9728 document.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name"`
}

// Supported protocol features. Metadata advertises exactly these.
var (
	GrantTypes  = []string{"authorization_code", "refresh_token"}
	AuthMethods = []string{"none", "client_secret_basic", "client_secret_post"}
)

// ResourceMetadata builds the RFC 9728 document for resource under issuer.
func ResourceMetadata(issuer string, resource Resource) ProtectedResourceMetadata {
	scopes := make([]string, len(resource.Scopes))
	for i, scope := range resource.Scopes {
		scopes[i] = string(scope)
	}
	return ProtectedResourceMetadata{Resource: resource.URI(issuer), AuthorizationServers: []string{issuer}, ScopesSupported: scopes, BearerMethodsSupported: []string{"header"}, ResourceName: resource.Name}
}

// Challenge builds an RFC 6750 / RFC 9728 WWW-Authenticate value. code is
// empty for a request without credentials, "invalid_token" or
// "insufficient_scope".
func Challenge(metadataURL, code, scope string) string {
	params := []string{}
	if code != "" {
		params = append(params, fmt.Sprintf("error=%q", code))
	}
	if scope != "" {
		params = append(params, fmt.Sprintf("scope=%q", scope))
	}
	params = append(params, fmt.Sprintf("resource_metadata=%q", metadataURL))
	return "Bearer " + strings.Join(params, ", ")
}
