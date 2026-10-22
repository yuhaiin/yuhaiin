package node

import (
	"github.com/Asutorufa/yuhaiin/pkg/credential"
	"testing"
)

func TestCredentialReferenceValidationAndResolution(t *testing.T) {
	for _, p := range []Protocol{
		{Type: "http", CredentialRef: "ref", HTTP: &HTTP{User: "inline"}},
		{Type: "yuubinsya", CredentialRef: "ref", Yuubinsya: &Yuubinsya{Password: "inline"}},
		{Type: "direct", CredentialRef: "ref", Direct: &Direct{}},
	} {
		if err := p.Validate(); err == nil {
			t.Fatalf("accepted conflicting/unsupported reference: %+v", p)
		}
	}
	p := Protocol{Type: "hysteria2", CredentialRef: "ref", Hysteria2: &Hysteria2{Host: "example.com:443", SalamanderPassword: "different"}}
	resolved, err := p.WithCredential(credential.Value{Type: credential.Password, Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Hysteria2.Auth != "" || p.CredentialRef != "ref" {
		t.Fatal("resolution mutated persisted config")
	}
	if resolved.CredentialRef != "" || resolved.Hysteria2.Auth != "secret" || resolved.Hysteria2.SalamanderPassword != "different" {
		t.Fatal("wrong credential field resolved")
	}
	if _, err := p.WithCredential(credential.Value{Type: credential.UsernamePassword, Password: "secret"}); err == nil {
		t.Fatal("wrong type resolved")
	}
}
