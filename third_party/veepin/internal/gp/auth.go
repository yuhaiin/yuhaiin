package gp

// The HTTPS control plane: prelogin, login, and logout.
//
// GlobalProtect splits its HTTPS surface between a portal (/global-protect/…)
// and a gateway (/ssl-vpn/…). The portal tells a client which gateways exist;
// the gateway is where a tunnel actually comes from. Only the gateway is needed
// to carry traffic, so that is what the server here implements, and what the
// client talks to — a portal that redirects is followed by pointing the client at
// the gateway it names.
//
// The login response is the protocol's oddest shape: a Java Web Start <jnlp>
// document whose <argument> elements are positional. Argument 1 is the
// authentication cookie that authorises everything afterwards. The indices below
// are the reference client's, and the order is the whole meaning of the document,
// so it is rendered and parsed by position rather than by name.

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
)

// Well-known GlobalProtect endpoints.
const (
	// PathPrelogin advertises what credentials the gateway wants.
	PathPrelogin = "/ssl-vpn/prelogin.esp"
	// PathLogin exchanges credentials for the authentication cookie.
	PathLogin = "/ssl-vpn/login.esp"
	// PathGetConfig returns the tunnel configuration, including the ESP keys.
	PathGetConfig = "/ssl-vpn/getconfig.esp"
	// PathLogout ends the session.
	PathLogout = "/ssl-vpn/logout.esp"
	// PathTunnel is the SSL data path. It is not under /ssl-vpn/.
	PathTunnel = "/ssl-tunnel-connect.sslvpn"
	// PathHIPCheck is the host-information-profile report check. A gateway that
	// requires one refuses the tunnel until the client submits it; this server
	// requires none, and answers so.
	PathHIPCheck = "/ssl-vpn/hipreportcheck.esp"

	// PathPortalPrelogin and PathPortalConfig are the portal's equivalents. The
	// server answers them so a client that starts at the portal — which the real
	// clients do — is pointed at this same host as its gateway.
	PathPortalPrelogin = "/global-protect/prelogin.esp"
	PathPortalConfig   = "/global-protect/getconfig.esp"
)

// TunnelStart is the response the gateway writes on the tunnel connection in
// place of an HTTP status line. A client that reads anything else has been given
// an error page and must not start framing packets.
const TunnelStart = "START_TUNNEL"

// clientVersion is the GlobalProtect client version this implementation reports.
// The gateway checks it: 4100 is what the reference client sends and what a
// server validates the login form against.
const clientVersion = "4100"

// BuildLoginForm renders the application/x-www-form-urlencoded body a client
// POSTs to login.esp. computer names the client host and is echoed in logs on the
// gateway; preferredIP asks for a particular inner address and may be empty,
// which asks the gateway to choose.
func BuildLoginForm(user, password, computer, preferredIP string) string {
	v := url.Values{}
	v.Set("prot", "https:")
	v.Set("server", "")
	v.Set("inputStr", "")
	v.Set("jnlpReady", "jnlpReady")
	v.Set("user", user)
	v.Set("passwd", password)
	v.Set("computer", computer)
	v.Set("ok", "Login")
	v.Set("direct", "yes")
	v.Set("clientVer", clientVersion)
	v.Set("os-version", "Linux")
	v.Set("clientos", "Linux")
	v.Set("preferred-ip", preferredIP)
	v.Set("ipv6-support", "no")
	return v.Encode()
}

// LoginRequest is a decoded login.esp form.
type LoginRequest struct {
	User        string
	Password    string
	Computer    string
	PreferredIP string
	ClientVer   string
}

// ParseLoginForm decodes the form body a client POSTed to login.esp.
func ParseLoginForm(body string) (LoginRequest, error) {
	v, err := url.ParseQuery(body)
	if err != nil {
		return LoginRequest{}, fmt.Errorf("gp: malformed login form: %w", err)
	}
	return LoginRequest{
		User:        v.Get("user"),
		Password:    v.Get("passwd"),
		Computer:    v.Get("computer"),
		PreferredIP: v.Get("preferred-ip"),
		ClientVer:   v.Get("clientVer"),
	}, nil
}

// LoginInfo is what a successful login yields. AuthCookie is the bearer token for
// getconfig and the tunnel; everything else is echoed back on those requests,
// which is the only reason a client keeps it.
type LoginInfo struct {
	AuthCookie       string
	PersistentCookie string
	Portal           string
	User             string
	Domain           string
	PreferredIP      string
}

// The positional <argument> slots of the login response. Only the ones this code
// reads or writes are named; the gaps are filled with the fixed values the
// reference client expects to see, which is what argDefaults holds.
const (
	argAuthCookie       = 1
	argPersistentCookie = 2
	argPortal           = 3
	argUser             = 4
	argDomain           = 7
	argConnectionType   = 12
	argPreferredIP      = 15
	// argCount is how many arguments the document carries. The reference client
	// tolerates a shorter list but reads by index, so a full one is rendered.
	argCount = 19
)

// argDefaults are the fixed values at the positions this implementation does not
// vary. The client validates two of them — the connection type must be "tunnel"
// and the version must match what it sent — so they are not decoration.
var argDefaults = map[int]string{
	0:  "(null)",
	5:  "veepin", // authentication source
	6:  "vsys1",  // configuration name
	8:  "(null)",
	12: "tunnel", // connection type; a client rejects anything else
	13: "-1",     // password expiry in days: never
	14: clientVersion,
}

// jnlp is the login response document. The argument list is positional, so it is
// modelled as a plain string slice rather than named fields.
type jnlp struct {
	XMLName xml.Name `xml:"jnlp"`
	App     struct {
		Arguments []string `xml:"argument"`
	} `xml:"application-desc"`
}

// BuildLoginResponse renders the <jnlp> document for a successful login.
func BuildLoginResponse(info LoginInfo) []byte {
	args := make([]string, argCount)
	for i, v := range argDefaults {
		args[i] = v
	}
	args[argAuthCookie] = info.AuthCookie
	args[argPersistentCookie] = info.PersistentCookie
	args[argPortal] = info.Portal
	args[argUser] = info.User
	args[argDomain] = info.Domain
	args[argPreferredIP] = info.PreferredIP

	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<jnlp><application-desc>")
	for _, a := range args {
		b.WriteString("<argument>")
		_ = xml.EscapeText(&b, []byte(a))
		b.WriteString("</argument>")
	}
	b.WriteString("</application-desc></jnlp>")
	return []byte(b.String())
}

// ParseLoginResponse decodes the <jnlp> document. A response without an
// authentication cookie is an error however well-formed it is: there is nothing
// a client can do with it.
func ParseLoginResponse(data []byte) (LoginInfo, error) {
	var doc jnlp
	if err := xml.Unmarshal(data, &doc); err != nil {
		return LoginInfo{}, fmt.Errorf("gp: parsing login response: %w", err)
	}
	args := doc.App.Arguments
	at := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	info := LoginInfo{
		AuthCookie:       at(argAuthCookie),
		PersistentCookie: at(argPersistentCookie),
		Portal:           at(argPortal),
		User:             at(argUser),
		Domain:           at(argDomain),
		PreferredIP:      at(argPreferredIP),
	}
	if info.AuthCookie == "" {
		return LoginInfo{}, fmt.Errorf("gp: login response carries no authentication cookie")
	}
	// "tunnel" is the only connection type that yields a VPN. A gateway offering
	// anything else has authenticated the user for something this client cannot
	// use, and saying so beats failing later on the tunnel request.
	if ct := at(argConnectionType); ct != "" && ct != "tunnel" {
		return LoginInfo{}, fmt.Errorf("gp: gateway offered connection type %q, want tunnel", ct)
	}
	return info, nil
}

// BuildGetConfigForm renders the body a client POSTs to getconfig.esp. The
// gateway matches the cookie against the session it issued, and echoes the
// address preference back in the configuration.
func BuildGetConfigForm(info LoginInfo, computer string) string {
	v := url.Values{}
	v.Set("user", info.User)
	v.Set("portal", info.Portal)
	v.Set("domain", info.Domain)
	v.Set("authcookie", info.AuthCookie)
	v.Set("preferred-ip", info.PreferredIP)
	v.Set("computer", computer)
	v.Set("client-type", "1")
	v.Set("protocol-version", "p1")
	v.Set("app-version", clientVersion)
	v.Set("clientos", "Linux")
	v.Set("os-version", "Linux")
	v.Set("hmac-algo", strings.Join(supportedHMACAlgos, ","))
	v.Set("enc-algo", strings.Join(supportedEncAlgos, ","))
	return v.Encode()
}

// GetConfigRequest is a decoded getconfig.esp form.
type GetConfigRequest struct {
	User        string
	AuthCookie  string
	PreferredIP string
	// EncAlgos and HMACAlgos are what the client says it can do, most preferred
	// first. A gateway picks from them.
	EncAlgos  []string
	HMACAlgos []string
}

// ParseGetConfigForm decodes the form body a client POSTed to getconfig.esp.
func ParseGetConfigForm(body string) (GetConfigRequest, error) {
	v, err := url.ParseQuery(body)
	if err != nil {
		return GetConfigRequest{}, fmt.Errorf("gp: malformed getconfig form: %w", err)
	}
	return GetConfigRequest{
		User:        v.Get("user"),
		AuthCookie:  v.Get("authcookie"),
		PreferredIP: v.Get("preferred-ip"),
		EncAlgos:    splitList(v.Get("enc-algo")),
		HMACAlgos:   splitList(v.Get("hmac-algo")),
	}, nil
}

// splitList decodes a comma-separated algorithm list, dropping empties so a
// trailing comma or an absent field yields no phantom entry.
func splitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Prelogin is the gateway's advertisement of what it will ask for.
type Prelogin struct {
	Status  string
	Message string
	// SAML reports that the gateway wants browser-based authentication, which
	// this client cannot do. It is surfaced so the failure names the reason.
	SAML bool
}

// preloginResponse mirrors the parts of the prelogin document read here.
type preloginResponse struct {
	XMLName    xml.Name `xml:"prelogin-response"`
	Status     string   `xml:"status"`
	Message    string   `xml:"authentication-message"`
	SAMLMethod string   `xml:"saml-auth-method"`
	SAMLReq    string   `xml:"saml-request"`
}

// BuildPreloginResponse renders the prelogin document for a password gateway.
func BuildPreloginResponse(message string) []byte {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<prelogin-response><status>Success</status><ccusername/>")
	b.WriteString("<autosubmit>false</autosubmit>")
	b.WriteString("<authentication-message>")
	_ = xml.EscapeText(&b, []byte(message))
	b.WriteString("</authentication-message>")
	b.WriteString("<username-label>Username</username-label><password-label>Password</password-label>")
	b.WriteString("</prelogin-response>")
	return []byte(b.String())
}

// ParsePreloginResponse decodes the prelogin document.
func ParsePreloginResponse(data []byte) (Prelogin, error) {
	var doc preloginResponse
	if err := xml.Unmarshal(data, &doc); err != nil {
		return Prelogin{}, fmt.Errorf("gp: parsing prelogin response: %w", err)
	}
	return Prelogin{
		Status:  doc.Status,
		Message: doc.Message,
		SAML:    doc.SAMLMethod != "" || doc.SAMLReq != "",
	}, nil
}

// BuildLogoutForm renders the body a client POSTs to logout.esp.
func BuildLogoutForm(info LoginInfo, computer string) string {
	v := url.Values{}
	v.Set("user", info.User)
	v.Set("portal", info.Portal)
	v.Set("domain", info.Domain)
	v.Set("authcookie", info.AuthCookie)
	v.Set("computer", computer)
	return v.Encode()
}

// TunnelRequest is the raw HTTP request that turns a fresh TLS connection into
// the packet tunnel. The gateway answers with TunnelStart rather than an HTTP
// status line, which is why this is written by hand rather than through net/http.
func TunnelRequest(host string, info LoginInfo) []byte {
	q := url.Values{}
	q.Set("user", info.User)
	q.Set("authcookie", info.AuthCookie)
	return []byte("GET " + PathTunnel + "?" + q.Encode() + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: PAN GlobalProtect\r\n" +
		"\r\n")
}

// ParseTunnelRequest pulls the user and cookie out of the tunnel request's query
// string, which is where the gateway authorises it from — there is no cookie
// header on this request.
func ParseTunnelRequest(rawQuery string) (user, authCookie string) {
	v, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", ""
	}
	return v.Get("user"), v.Get("authcookie")
}
