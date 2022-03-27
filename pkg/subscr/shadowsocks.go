package subscr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"

	ssClient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
)

var DefaultShadowsocks = &shadowsocks{}

type shadowsocks struct{}

func (*shadowsocks) ParseLink(str []byte) (*Point, error) {
	n := new(Shadowsocks)
	ssUrl, err := url.Parse(string(str))
	if err != nil {
		return nil, err
	}
	n.Server = ssUrl.Hostname()
	n.Port = ssUrl.Port()
	n.Method = strings.Split(DecodeUrlBase64(ssUrl.User.String()), ":")[0]
	n.Password = strings.Split(DecodeUrlBase64(ssUrl.User.String()), ":")[1]
	n.Plugin = strings.Split(ssUrl.Query().Get("plugin"), ";")[0]
	n.PluginOpt = strings.Replace(ssUrl.Query().Get("plugin"), n.Plugin+";", "", -1)

	p := &Point{
		NOrigin: Point_remote,
		NName:   "[ss]" + ssUrl.Fragment,
		Node:    &Point_Shadowsocks{Shadowsocks: n},
	}
	z := sha256.Sum256([]byte(p.String()))
	p.NHash = hex.EncodeToString(z[:])

	return p, nil
}

func (p *Point_Shadowsocks) Conn() (proxy.Proxy, error) {
	s := p.Shadowsocks
	if s == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}
	var py proxy.Proxy = simple.NewSimple(s.Server, s.Port)

	var plugin func(string) (func(proxy.Proxy) (proxy.Proxy, error), error)
	switch strings.ToLower(s.Plugin) {
	case "obfs-local":
		plugin = NewObfs
	case "v2ray":
		plugin = NewV2raySelf
	default:
		plugin = func(s string) (func(proxy.Proxy) (proxy.Proxy, error), error) {
			return func(p proxy.Proxy) (proxy.Proxy, error) { return p, nil }, nil
		}
	}
	pluginC, err := plugin(s.PluginOpt)
	if err != nil {
		return nil, fmt.Errorf("init plugin failed: %w", err)
	}
	py, err = pluginC(py)
	if err != nil {
		return nil, fmt.Errorf("init plugin failed: %w", err)
	}
	return ssClient.NewShadowsocks(s.Method, s.Password, s.Server, s.Port)(py)
}

func NewV2raySelf(options string) (func(proxy.Proxy) (proxy.Proxy, error), error) {
	// fastOpen := false
	path := "/"
	host := "cloudfront.com"
	tlsEnabled := false
	cert := ""
	// certRaw := ""
	mode := "websocket"

	for _, x := range strings.Split(options, ";") {
		if !strings.Contains(x, "=") {
			if x == "tls" {
				tlsEnabled = true
			}
			continue
		}
		s := strings.Split(x, "=")
		switch s[0] {
		case "mode":
			mode = s[1]
		case "path":
			path = s[1]
		case "cert":
			cert = s[1]
		case "host":
			host = s[1]
			// case "certRaw":
			// certRaw = s[1]
			// case "fastOpen":
			// fastOpen = true
		}
	}

	switch mode {
	case "websocket":
		return websocket.NewWebsocket(host, path, false, tlsEnabled, []string{cert}), nil
	case "quic":
		return quic.NewQUIC(host, []string{cert}, false), nil
	}

	return nil, fmt.Errorf("unsupported mode")
}

func NewObfs(pluginOpt string) (func(proxy.Proxy) (proxy.Proxy, error), error) {
	args := make(map[string]string)
	for _, x := range strings.Split(pluginOpt, ";") {
		if strings.Contains(x, "=") {
			s := strings.Split(x, "=")
			args[s[0]] = s[1]
		}
	}
	switch args["obfs"] {
	case "http":
		hostname, port, err := net.SplitHostPort(args["obfs-host"])
		if err != nil {
			return nil, err
		}
		return ssClient.NewHTTPOBFS(hostname, port), nil
	default:
		return nil, errors.New("not support plugin")
	}
}
