package fortinet

// The HTTPS login exchange at /remote/logincheck.
//
// The client POSTs a form; on success FortiOS answers with a short text line —
// ret=1,redir=/remote/fortisslvpn_xml — and sets the SVPNCOOKIE that authorises
// every later request. This file is just those two shapes: building and parsing
// the form, and building and parsing the response line. The cookie itself is an
// opaque bearer token, minted by the server and echoed back by the client.

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Well-known Fortinet SSL VPN endpoints and the session cookie name.
const (
	PathLoginCheck = "/remote/logincheck"
	PathConfigXML  = "/remote/fortisslvpn_xml"
	PathTunnel     = "/remote/sslvpn-tunnel"
	CookieName     = "SVPNCOOKIE"
)

// BuildLoginForm renders the application/x-www-form-urlencoded body a client
// POSTs to /remote/logincheck. realm may be empty. ajax=1 and just_logged_in=1
// are what the FortiOS web client sends and what the server expects to see.
func BuildLoginForm(username, password, realm string) string {
	v := url.Values{}
	v.Set("username", username)
	v.Set("credential", password)
	v.Set("realm", realm)
	v.Set("ajax", "1")
	v.Set("just_logged_in", "1")
	return v.Encode()
}

// LoginRequest is a decoded /remote/logincheck form.
type LoginRequest struct {
	Username string
	Password string
	Realm    string
}

// ParseLoginForm decodes the form body a client POSTed.
func ParseLoginForm(body string) (LoginRequest, error) {
	v, err := url.ParseQuery(body)
	if err != nil {
		return LoginRequest{}, fmt.Errorf("fortinet: malformed login form: %w", err)
	}
	return LoginRequest{
		Username: v.Get("username"),
		Password: v.Get("credential"),
		Realm:    v.Get("realm"),
	}, nil
}

// BuildLoginSuccess renders the response line for a successful login. redir is
// the path the client is told to fetch next, normally PathConfigXML.
func BuildLoginSuccess(redir string) string {
	return "ret=1,redir=" + redir
}

// LoginResult is a decoded /remote/logincheck response line.
type LoginResult struct {
	// Ret is the numeric status: 1 success, 2 challenge (2FA), other failures.
	Ret int
	// Redir is the follow-up path on success.
	Redir string
	// Fields holds every key=value pair, so a caller handling a challenge can
	// read reqid/polid/grp without this needing to know them.
	Fields map[string]string
}

// ParseLoginResult decodes the ret=…,redir=… response line.
func ParseLoginResult(line string) (LoginResult, error) {
	res := LoginResult{Ret: -1, Fields: map[string]string{}}
	for part := range strings.SplitSeq(strings.TrimSpace(line), ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		res.Fields[k] = v
		switch k {
		case "ret":
			if n, err := strconv.Atoi(v); err == nil {
				res.Ret = n
			}
		case "redir":
			res.Redir = v
		}
	}
	if res.Ret < 0 {
		return LoginResult{}, fmt.Errorf("fortinet: login response has no ret: %q", line)
	}
	return res, nil
}

// The two-factor challenge.
//
// A gateway that wants a second factor answers the first POST with ret=2 and a
// tokeninfo field instead of a cookie. The client then POSTs a second form: the
// same username, the one-time code under the name "code" rather than
// "credential", and a set of opaque values from the challenge response that it
// parrots back unchanged. Those values are the server's whole memory of the
// exchange, so they must survive the round trip byte for byte.
//
// The layouts here are openconnect's, verified against its fortinet.c.

// challengeEcho is the set of fields a client echoes from the challenge back to
// the gateway, in the order openconnect sends them. The order is not cosmetic:
// "magic" must be last, because the ftm_push variant truncates the body at
// "&magic=" to drop it and everything after.
var challengeEcho = []string{"reqid", "polid", "grp", "portal", "peer", "magic"}

// Challenge is a decoded second-factor prompt.
type Challenge struct {
	// Message is the gateway's prompt, if it sent one (chal_msg).
	Message string
	// TokenInfo names the challenge kind, e.g. "ftm_push" for a mobile push.
	TokenInfo string
	// Echo holds the opaque values to send back, keyed by name.
	Echo map[string]string
}

// FTMPush reports whether the gateway offered a mobile-push approval, which a
// client can trigger by submitting an empty code.
func (c Challenge) FTMPush() bool { return c.TokenInfo == "ftm_push" }

// IsChallenge reports whether a login response is a second-factor prompt. The
// presence of tokeninfo is the signal, as it is in openconnect: ret carries the
// status, but tokeninfo is what says a second stage exists.
func (r LoginResult) IsChallenge() bool {
	_, ok := r.Fields["tokeninfo"]
	return ok
}

// Challenge decodes the second-factor prompt from a login response.
func (r LoginResult) Challenge() Challenge {
	c := Challenge{
		Message:   r.Fields["chal_msg"],
		TokenInfo: r.Fields["tokeninfo"],
		Echo:      map[string]string{},
	}
	for _, k := range challengeEcho {
		if v, ok := r.Fields[k]; ok {
			c.Echo[k] = v
		}
	}
	return c
}

// BuildChallengeResponse renders the response line for a login that needs a
// second factor. echo are the opaque values the client must send back; message
// is an optional prompt shown to the user.
func BuildChallengeResponse(message string, echo map[string]string) string {
	var b strings.Builder
	b.WriteString("ret=2,tokeninfo=")
	for _, k := range challengeEcho {
		if v, ok := echo[k]; ok {
			fmt.Fprintf(&b, ",%s=%s", k, v)
		}
	}
	if message != "" {
		fmt.Fprintf(&b, ",chal_msg=%s", message)
	}
	return b.String()
}

// BuildChallengeForm renders the second-stage form body. An empty code with an
// ftm_push challenge is the mobile-push request: "magic" is dropped and
// ftmpush=1 takes its place, which is what tells the gateway to poll the user's
// phone instead of checking a typed code.
func BuildChallengeForm(username, code, realm string, c Challenge) string {
	var b strings.Builder
	// Built by hand rather than with url.Values, whose Encode sorts keys
	// alphabetically -- that would move "magic" out of last place and break the
	// push variant.
	fmt.Fprintf(&b, "username=%s&code=%s&realm=%s",
		url.QueryEscape(username), url.QueryEscape(code), url.QueryEscape(realm))

	push := c.FTMPush() && code == ""
	for _, k := range challengeEcho {
		v, ok := c.Echo[k]
		if !ok {
			continue
		}
		if k == "magic" && push {
			continue
		}
		fmt.Fprintf(&b, "&%s=%s", k, url.QueryEscape(v))
	}
	if push {
		b.WriteString("&ftmpush=1")
	}
	return b.String()
}

// ChallengeRequest is a decoded second-stage form.
type ChallengeRequest struct {
	Username string
	Code     string
	Realm    string
	// Echo holds the values the client sent back.
	Echo map[string]string
	// FTMPush is true when the client asked for a mobile push instead of
	// submitting a code.
	FTMPush bool
}

// ParseChallengeForm decodes the second-stage form a client POSTed.
func ParseChallengeForm(body string) (ChallengeRequest, error) {
	v, err := url.ParseQuery(body)
	if err != nil {
		return ChallengeRequest{}, fmt.Errorf("fortinet: malformed challenge form: %w", err)
	}
	req := ChallengeRequest{
		Username: v.Get("username"),
		Code:     v.Get("code"),
		Realm:    v.Get("realm"),
		Echo:     map[string]string{},
		FTMPush:  v.Get("ftmpush") == "1",
	}
	for _, k := range challengeEcho {
		if v.Has(k) {
			req.Echo[k] = v.Get(k)
		}
	}
	return req, nil
}

// IsChallengeForm reports whether a POSTed body is a second-stage submission
// rather than a first-stage login, so one endpoint can serve both as FortiOS
// does. A first-stage form carries "credential"; a second-stage one carries
// "reqid", the handle for the exchange in progress.
func IsChallengeForm(body string) bool {
	v, err := url.ParseQuery(body)
	if err != nil {
		return false
	}
	return v.Has("reqid")
}
