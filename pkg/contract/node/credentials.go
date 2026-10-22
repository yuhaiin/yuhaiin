package node

import (
	"errors"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/credential"
)

// CredentialType describes the authentication material consumed by this layer.
// Non-authentication fields, including obfuscation passwords, remain inline.
func (p Protocol) CredentialType() (kind string, inline bool) {
	switch p.Type {
	case "http":
		return credential.UsernamePassword, p.HTTP.User != "" || p.HTTP.Password != ""
	case "socks5":
		return credential.UsernamePassword, p.Socks5.User != "" || p.Socks5.Password != ""
	case "yuubinsya":
		return credential.Password, p.Yuubinsya.Password != ""
	case "hysteria2":
		return credential.Password, p.Hysteria2.Auth != ""
	case "shadowsocks":
		return credential.Password, p.Shadowsocks.Password != ""
	case "shadowsocksr":
		return credential.Password, p.Shadowsocksr.Password != ""
	case "trojan":
		return credential.Password, p.Trojan.Password != ""
	case "aead":
		return credential.Password, p.AEAD.Password != ""
	default:
		return "", false
	}
}

func (p Protocol) validateCredentialRef() error {
	if p.CredentialRef == "" {
		return nil
	}
	if len(p.CredentialRef) > 128 || strings.TrimSpace(p.CredentialRef) != p.CredentialRef {
		return errors.New("invalid credential reference")
	}
	kind, inline := p.CredentialType()
	if kind == "" {
		return errors.New("credential reference is unsupported by this protocol")
	}
	if inline {
		return errors.New("credential reference conflicts with inline authentication fields")
	}
	return nil
}

// WithCredential copies only the selected payload. Resolving a reference must
// never mutate the persisted node or expose its secret in configuration reads.
func (p Protocol) WithCredential(value credential.Value) (Protocol, error) {
	if err := p.Validate(); err != nil {
		return Protocol{}, err
	}
	kind, _ := p.CredentialType()
	if p.CredentialRef == "" || kind == "" || kind != value.Type {
		return Protocol{}, errors.New("credential type is incompatible with protocol")
	}
	switch p.Type {
	case "http":
		v := *p.HTTP
		v.User, v.Password = value.Username, value.Password
		p.HTTP = &v
	case "socks5":
		v := *p.Socks5
		v.User, v.Password = value.Username, value.Password
		p.Socks5 = &v
	case "yuubinsya":
		v := *p.Yuubinsya
		v.Password = value.Password
		p.Yuubinsya = &v
	case "hysteria2":
		v := *p.Hysteria2
		v.Auth = value.Password
		p.Hysteria2 = &v
	case "shadowsocks":
		v := *p.Shadowsocks
		v.Password = value.Password
		p.Shadowsocks = &v
	case "shadowsocksr":
		v := *p.Shadowsocksr
		v.Password = value.Password
		p.Shadowsocksr = &v
	case "trojan":
		v := *p.Trojan
		v.Password = value.Password
		p.Trojan = &v
	case "aead":
		v := *p.AEAD
		v.Password = value.Password
		p.AEAD = &v
	}
	p.CredentialRef = ""
	return p, nil
}
