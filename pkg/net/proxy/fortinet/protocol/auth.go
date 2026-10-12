package fortinet

// The client POSTs login forms, reads FortiOS's short response line, and echoes
// the SVPNCOOKIE on later requests. The cookie is an opaque bearer token.

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
