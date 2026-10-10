// Package globalprotect implements the SSL (IP over TLS) mode of Palo Alto
// GlobalProtect gateways. ESP, SAML/SSO and HIP reporting are not supported.
// Protocol observations: https://github.com/dlenski/openconnect/blob/master/PAN_GlobalProtect_protocol_doc.md
package globalprotect

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "encoding/xml"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/netip"
 "net/url"
 "os"
 "strings"
 "time"

 "github.com/Asutorufa/yuhaiin/pkg/net/dialer"
 "github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const (
 clientOS = "Windows"
 clientVersion = "5.1.5-8"
 osVersion = "Microsoft Windows 10, 64-bit"
 maxControlBody = 1 << 20
 defaultMTU = 1300
)

var ErrInteractiveAuth = errors.New("globalprotect: SAML/SSO or interactive challenge is unsupported")

// Config intentionally has no insecure_skip_verify setting. Enterprises can
// supply a trusted CA PEM instead of disabling gateway authentication.
type Config struct {
 Gateway string
 Username string
 Password string
 Computer string
 CACertPEM string
 MTU int
}

type session struct {
 User string
 Cookie string
 Portal string
 Domain string
 PreferredIP string
}

type gatewayConfig struct {
 XMLName xml.Name `xml:"response"`
 Status string `xml:"status,attr"`
 Error string `xml:"error"`
 NeedTunnel string `xml:"need-tunnel"`
 IPAddress string `xml:"ip-address"`
 Netmask string `xml:"netmask"`
 TunnelURL string `xml:"ssl-tunnel-url"`
 Timeout int `xml:"timeout"`
 MTU int `xml:"mtu"`
 DNS []string `xml:"dns>member"`
 AccessRoutes []string `xml:"access-routes>member"`
 ExcludeRoutes []string `xml:"exclude-access-routes>member"`
}

type jnlpResponse struct {
 XMLName xml.Name `xml:"jnlp"`
 Arguments []string `xml:"application-desc>argument"`
}

type preloginResponse struct {
 XMLName xml.Name `xml:"prelogin-response"`
 Status string `xml:"status"`
 Message string `xml:"msg"`
 SAMLStatus string `xml:"saml-auth-status"`
 SAMLRequest string `xml:"saml-request"`
}

type control struct {
 gateway *url.URL
 tlsConfig *tls.Config
 client *http.Client
 transport *http.Transport
 dial func(context.Context, string) (net.Conn, error)
 computer string
}

func parseGateway(raw string) (*url.URL, error) {
 if raw == "" { return nil, errors.New("globalprotect: gateway is empty") }
 if !strings.Contains(raw, "://") { raw = "https://" + raw }
 u, err := url.Parse(raw)
 if err != nil { return nil, fmt.Errorf("globalprotect: invalid gateway: %w", err) }
 if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
  return nil, errors.New("globalprotect: gateway must be an HTTPS hostname with optional port, without path or credentials")
 }
 if port := u.Port(); port != "" {
  if _, err := netip.ParseAddrPort(net.JoinHostPort("127.0.0.1", port)); err != nil {
   return nil, fmt.Errorf("globalprotect: invalid gateway port: %w", err)
  }
 }
 return u, nil
}

func newControl(c Config) (*control, error) {
 gateway, err := parseGateway(c.Gateway)
 if err != nil { return nil, err }
 roots, err := x509.SystemCertPool()
 if err != nil || roots == nil { roots = x509.NewCertPool() }
 if c.CACertPEM != "" && !roots.AppendCertsFromPEM([]byte(c.CACertPEM)) {
  return nil, errors.New("globalprotect: invalid CA certificate PEM")
 }
 tlsConfig := &tls.Config{ServerName: gateway.Hostname(), MinVersion: tls.VersionTLS12, RootCAs: roots}
 tcpDial := func(ctx context.Context, address string) (net.Conn, error) {
  a, err := netapi.ParseAddress("tcp", address)
  if err != nil { return nil, err }
  return dialer.DialHappyEyeballsv1(ctx, a)
 }
 tr := &http.Transport{
  TLSClientConfig: tlsConfig,
  DisableKeepAlives: true,
  ForceAttemptHTTP2: false,
  DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
   return tcpDial(ctx, address)
  },
 }
 computer := c.Computer
 if computer == "" { computer, _ = os.Hostname() }
 if computer == "" { computer = "yuhaiin" }
 return &control{
  gateway: gateway, tlsConfig: tlsConfig, transport: tr, dial: tcpDial, computer: computer,
  client: &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
   return http.ErrUseLastResponse
  }},
 }, nil
}

func (c *control) close() { c.transport.CloseIdleConnections() }

func (c *control) dialTLS(ctx context.Context) (*tls.Conn, error) {
 address := c.gateway.Host
 if c.gateway.Port() == "" { address = net.JoinHostPort(c.gateway.Hostname(), "443") }
 raw, err := c.dial(ctx, address)
 if err != nil { return nil, err }
 conn := tls.Client(raw, c.tlsConfig.Clone())
 if err = conn.HandshakeContext(ctx); err != nil {
  _ = conn.Close()
  return nil, err
 }
 return conn, nil
}

func (c *control) post(ctx context.Context, path string, form url.Values) ([]byte, error) {
 target := *c.gateway
 targetPath, err := url.Parse(path)
 if err != nil || !strings.HasPrefix(targetPath.Path, "/") || targetPath.IsAbs() || targetPath.Host != "" { return nil, errors.New("globalprotect: invalid control URL path") }
 target.Path = targetPath.Path
 target.RawQuery = targetPath.RawQuery
 req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(form.Encode()))
 if err != nil { return nil, err }
 req.Header.Set("User-Agent", "PAN GlobalProtect")
 req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
 resp, err := c.client.Do(req)
 if err != nil { return nil, err }
 defer resp.Body.Close()
 if resp.StatusCode != http.StatusOK {
  return nil, fmt.Errorf("globalprotect: %s returned HTTP %d", path, resp.StatusCode)
 }
 b, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBody + 1))
 if err != nil { return nil, err }
 if len(b) > maxControlBody { return nil, errors.New("globalprotect: oversized control response") }
 return b, nil
}

func (c *control) prelogin(ctx context.Context) error {
 data, err := c.post(ctx, "/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Windows", url.Values{"cas-support":{"yes"}})
 if err != nil { return err }
 var p preloginResponse
 if err := xml.Unmarshal(data, &p); err != nil { return fmt.Errorf("globalprotect: prelogin XML: %w", err) }
 if p.XMLName.Local != "prelogin-response" {
  return errors.New("globalprotect: unexpected prelogin response (portal-only gateway or interactive authentication)")
 }
 if p.SAMLRequest != "" || (p.SAMLStatus != "" && p.SAMLStatus != "0") { return ErrInteractiveAuth }
 if !strings.EqualFold(p.Status, "success") {
  return fmt.Errorf("globalprotect: prelogin refused: %s", p.Message)
 }
 return nil
}

func commonLoginForm(c *control, user, pass string) url.Values {
 return url.Values{
  "user":{user}, "passwd":{pass}, "computer":{c.computer},
  "prot":{"https:"}, "server":{c.gateway.Hostname()}, "jnlpReady":{"jnlpReady"},
  "ok":{"Login"}, "direct":{"yes"}, "clientVer":{"4100"},
  "clientos":{clientOS}, "os-version":{osVersion}, "clientgpversion":{clientVersion},
 }
}

func parseLogin(data []byte) (session, error) {
 var response jnlpResponse
 if err := xml.Unmarshal(data, &response); err != nil { return session{}, fmt.Errorf("globalprotect: login XML: %w", err) }
 if response.XMLName.Local != "jnlp" || len(response.Arguments) < 8 {
  return session{}, errors.New("globalprotect: gateway login failed or requires interactive authentication")
 }
 args := response.Arguments
 s := session{Cookie: args[1], Portal: args[3], User: args[4], Domain: args[7]}
 if len(args) > 15 { s.PreferredIP = args[15] }
 if s.User == "" || s.Cookie == "" || s.Cookie == "(null)" {
  return session{}, errors.New("globalprotect: login response lacks authentication cookie or username")
 }
 if s.Portal == "(null)" { s.Portal = "" }
 if s.Domain == "(null)" { s.Domain = "" }
 if decoded, err := url.QueryUnescape(s.Domain); err == nil { s.Domain = decoded }
 return s, nil
}

func (c *control) login(ctx context.Context, user, pass string) (session, error) {
 if user == "" || pass == "" { return session{}, errors.New("globalprotect: username and password required") }
 data, err := c.post(ctx, "/ssl-vpn/login.esp", commonLoginForm(c, user, pass))
 if err != nil { return session{}, err }
 return parseLogin(data)
}

func (c *control) getConfig(ctx context.Context, s session) (gatewayConfig, netip.Prefix, error) {
 values := url.Values{
  "user":{s.User}, "authcookie":{s.Cookie}, "portal":{s.Portal},
  "client-type":{"1"}, "protocol-version":{"p1"}, "app-version":{clientVersion},
  "clientos":{clientOS}, "os-version":{osVersion},
  "enc-algo":{"aes-128-cbc"}, "hmac-algo":{"sha1"},
 }
 if s.PreferredIP != "" && s.PreferredIP != "(null)" { values.Set("preferred-ip", s.PreferredIP) }
 data, err := c.post(ctx, "/ssl-vpn/getconfig.esp", values)
 if err != nil { return gatewayConfig{}, netip.Prefix{}, err }
 var cfg gatewayConfig
 if err := xml.Unmarshal(data, &cfg); err != nil { return cfg, netip.Prefix{}, fmt.Errorf("globalprotect: config XML: %w", err) }
 if cfg.XMLName.Local != "response" || !strings.EqualFold(cfg.Status, "success") {
  return cfg, netip.Prefix{}, fmt.Errorf("globalprotect: getconfig refused: %s", cfg.Error)
 }
 if !strings.EqualFold(cfg.NeedTunnel, "yes") { return cfg, netip.Prefix{}, errors.New("globalprotect: gateway did not enable IP tunnel") }
 ip, err := netip.ParseAddr(cfg.IPAddress)
 if err != nil || !ip.Is4() { return cfg, netip.Prefix{}, errors.New("globalprotect: missing or unsupported IPv4 tunnel address") }
 bits := 32
 if cfg.Netmask != "" {
  mask := net.ParseIP(cfg.Netmask).To4()
  if mask == nil { return cfg, netip.Prefix{}, errors.New("globalprotect: invalid gateway netmask") }
  ones, total := net.IPMask(mask).Size()
  if total != 32 || ones < 0 { return cfg, netip.Prefix{}, errors.New("globalprotect: noncontiguous gateway netmask") }
  bits = ones
 }
 if cfg.TunnelURL == "" { cfg.TunnelURL = "/ssl-tunnel-connect.sslvpn" }
 tunnelURL, err := url.Parse(cfg.TunnelURL)
 if err != nil || !strings.HasPrefix(cfg.TunnelURL, "/") || tunnelURL.IsAbs() || tunnelURL.Host != "" {
  return cfg, netip.Prefix{}, errors.New("globalprotect: invalid gateway tunnel URL")
 }
 return cfg, netip.PrefixFrom(ip, bits), nil
}

func (c *control) logout(ctx context.Context, s session) error {
 values := url.Values{
  "user":{s.User}, "portal":{s.Portal}, "authcookie":{s.Cookie},
  "domain":{s.Domain}, "computer":{c.computer}, "os-version":{osVersion},
 }
 _, err := c.post(ctx, "/ssl-vpn/logout.esp", values)
 return err
}

