package fortinet

// The client engine: the HTTPS login, then the framed PPP data path.
//
// Login is ordinary HTTP over the caller's TLS-configured http.Client (with a
// cookie jar, so the SVPNCOOKIE flows from the login to the config fetch). The
// data path is separate: the caller opens a fresh TLS connection, sends the
// tunnel GET, and hands the raw connection here, where PPP runs over the 6-octet
// framing until the link carries IP.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/ppp"
	"github.com/xen0bit/veepin/internal/vlog"
)

// ErrAuth reports rejected credentials, so a caller can tell a bad password from
// a transport failure.
var ErrAuth = errors.New("fortinet: authentication failed")

// networkUpTimeout bounds how long the data path waits for IPCP to bring the
// link up before giving up.
const networkUpTimeout = 20 * time.Second

// TokenFunc supplies the one-time code for a second-factor challenge. It
// receives the gateway's prompt so a caller can show it, and returns the code to
// submit. Returning an empty code against an ftm_push challenge requests a
// mobile push approval instead of a typed code.
//
// A nil TokenFunc means the caller cannot answer a challenge, and a gateway that
// asks for one fails the login rather than hanging.
type TokenFunc func(Challenge) (string, error)

// ErrChallenge reports that the gateway demanded a second factor the caller was
// not equipped to answer, so it can be told apart from a wrong password.
var ErrChallenge = errors.New("fortinet: the gateway requires a second factor")

// Login performs the /remote/logincheck exchange and fetches the tunnel config.
// hc must carry a cookie jar so the SVPNCOOKIE it receives is sent on the config
// fetch. base is the server's https:// origin. token answers a second-factor
// challenge and may be nil where none is expected. It returns the parsed config
// and the SVPNCOOKIE value, which the caller puts on the tunnel request.
func Login(hc *http.Client, base, username, password, realm string, token TokenFunc) (Config, string, error) {
	form := BuildLoginForm(username, password, realm)
	result, err := postLogin(hc, base, form)
	if err != nil {
		return Config{}, "", err
	}

	// A gateway that wants a second factor answers the password with a challenge
	// rather than a cookie; answering it correctly resumes the same exchange.
	if result.IsChallenge() {
		result, err = answerChallenge(hc, base, username, realm, result.Challenge(), token)
		if err != nil {
			return Config{}, "", err
		}
	}
	if result.Ret != 1 {
		return Config{}, "", fmt.Errorf("%w: login returned ret=%d", ErrAuth, result.Ret)
	}

	cookie := cookieValue(hc, base)
	if cookie == "" {
		return Config{}, "", fmt.Errorf("fortinet: server issued no %s", CookieName)
	}

	redir := result.Redir
	if redir == "" {
		redir = PathConfigXML
	}
	cfgResp, err := hc.Get(base + redir)
	if err != nil {
		return Config{}, "", fmt.Errorf("fortinet: config request: %w", err)
	}
	cfgBody, _ := io.ReadAll(cfgResp.Body)
	_ = cfgResp.Body.Close()

	cfg, err := ParseConfigXML(cfgBody)
	if err != nil {
		return Config{}, "", err
	}
	return cfg, cookie, nil
}

// postLogin submits a logincheck form and decodes the response line.
func postLogin(hc *http.Client, base, form string) (LoginResult, error) {
	resp, err := hc.Post(base+PathLoginCheck, "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		return LoginResult{}, fmt.Errorf("fortinet: login request: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()

	// A rejected login is an HTTP error with no parsable line, so it is reported
	// as an auth failure rather than as a malformed response.
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusMethodNotAllowed {
		return LoginResult{}, fmt.Errorf("%w: gateway returned %s", ErrAuth, resp.Status)
	}
	return ParseLoginResult(string(body))
}

// answerChallenge submits the second factor and returns the follow-up result.
func answerChallenge(hc *http.Client, base, username, realm string, c Challenge, token TokenFunc) (LoginResult, error) {
	if token == nil {
		if c.Message != "" {
			return LoginResult{}, fmt.Errorf("%w: %s", ErrChallenge, c.Message)
		}
		return LoginResult{}, ErrChallenge
	}
	code, err := token(c)
	if err != nil {
		return LoginResult{}, fmt.Errorf("fortinet: obtaining the token code: %w", err)
	}
	result, err := postLogin(hc, base, BuildChallengeForm(username, code, realm, c))
	if err != nil {
		return LoginResult{}, err
	}
	// One challenge is answered once. A gateway that keeps asking is either
	// misconfigured or the code is wrong, and looping would only make it worse.
	if result.IsChallenge() {
		return LoginResult{}, fmt.Errorf("%w: the gateway rejected the token code", ErrAuth)
	}
	return result, nil
}

// TunnelRequest is the raw HTTP request that turns a fresh TLS connection into
// the framed PPP tunnel. The caller writes it, then hands the connection to
// RunClient; no HTTP response follows on success (the server begins framing PPP
// immediately), which is why this is written by hand rather than through
// net/http.
func TunnelRequest(host, cookie string) []byte {
	return []byte("GET " + PathTunnel + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 SV1\r\n" +
		"Cookie: " + CookieName + "=" + cookie + "\r\n" +
		"\r\n")
}

// Client is an established Fortinet tunnel.
type Client struct {
	link *pppLink
	cfg  Config
}

// AssignedConfig is the tunnel configuration the login returned.
func (c *Client) AssignedConfig() Config { return c.cfg }

// RunClient drives PPP over the tunnel connection and binds it to tun. conn must
// already have had the tunnel GET written to it. cfg is the configuration from
// Login, used for the returned Result; the link itself confirms the address over
// IPCP.
func RunClient(conn net.Conn, cfg Config, tun io.ReadWriteCloser, logger *vlog.Logger) (*Client, error) {
	return runClient(conn, cfg, tun, logger, false)
}

// RunDTLSClient is RunClient over the UDP data channel: conn is the established
// DTLS session from DialDTLS, which has already presented the cookie, and each
// datagram carries exactly one framed record.
func RunDTLSClient(conn net.Conn, cfg Config, tun io.ReadWriteCloser, logger *vlog.Logger) (*Client, error) {
	return runClient(conn, cfg, tun, logger, true)
}

func runClient(conn net.Conn, cfg Config, tun io.ReadWriteCloser, logger *vlog.Logger, datagram bool) (*Client, error) {
	if logger == nil {
		logger = vlog.Discard()
	}
	h := &clientHandler{ready: make(chan struct{}), closed: make(chan error, 1)}

	// The link is the PPP transport, so it is built first; the session is created
	// with it and then registered back on the link for inbound control frames.
	// No PPP-level credentials: the SVPNCOOKIE already authenticated, so the
	// server will not request authentication and the link goes LCP->IPCP.
	link := &pppLink{conn: conn, tun: tun, ownsTUN: true, datagram: datagram, logger: logger, done: make(chan struct{})}
	sess := ppp.New("", "", link, h)
	link.client = sess

	go link.readLoop()
	sess.Start()

	select {
	case <-h.ready:
		go link.tunLoop()
		logger.Printf("fortinet: tunnel up, assigned %s", cfg.AssignedIP)
		return &Client{link: link, cfg: cfg}, nil
	case err := <-h.closed:
		_ = link.Close()
		return nil, fmt.Errorf("fortinet: link closed during setup: %w", err)
	case <-time.After(networkUpTimeout):
		_ = link.Close()
		return nil, fmt.Errorf("fortinet: timed out waiting for the link to come up")
	}
}

// AttachDTLS adds an established DTLS session to a running tunnel and makes it
// the egress, which is how a real client uses the UDP channel: the TLS tunnel
// stays open as the fallback, and losing UDP costs a detach rather than the
// tunnel. conn comes from DialDTLS, which has already presented the cookie.
func (c *Client) AttachDTLS(conn net.Conn) { c.link.attachDTLS(conn) }

// Probe sends an LCP Echo-Request and waits for the peer's Echo-Reply.
//
// It goes out over whichever carrier the link is currently using, which is the
// point: a DTLS carrier is the egress while it lives, and it can stop
// delivering without ever producing a read error -- an expired NAT binding is
// the ordinary way. readAlt detaches on an error, and silence is not one, so a
// dead UDP path sits underneath a healthy TLS connection with the tunnel
// reporting itself up and carrying nothing.
func (c *Client) Probe(ctx context.Context) error { return c.link.probe(ctx) }

// Wait blocks until the tunnel stops.
func (c *Client) Wait() error { return c.link.Wait() }

// Close tears the tunnel down.
func (c *Client) Close() error { return c.link.Close() }

// clientHandler bridges PPP lifecycle events to the setup handshake.
type clientHandler struct {
	ready  chan struct{}
	closed chan error
	cfg    ppp.IPConfig
	once   sync.Once
}

func (h *clientHandler) Authenticated(_ [mschap.NTResponseLen]byte) {}
func (h *clientHandler) NetworkUp(cfg ppp.IPConfig) {
	h.cfg = cfg
	h.once.Do(func() { close(h.ready) })
}
func (h *clientHandler) Closed(err error) {
	select {
	case h.closed <- err:
	default:
	}
}

// cookieValue pulls the SVPNCOOKIE out of the client's jar for the server URL.
func cookieValue(hc *http.Client, base string) string {
	if hc.Jar == nil {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	for _, c := range hc.Jar.Cookies(u) {
		if c.Name == CookieName {
			return c.Value
		}
	}
	return ""
}
