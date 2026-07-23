package user

import (
	json "encoding/json/v2"
	"strings"
	"testing"
)

func TestCredentialValidateVariants(t *testing.T) {
	username, password := "alice", "secret"
	tests := []struct {
		name    string
		value   Credential
		wantErr bool
	}{
		{
			name:  "basic username and password",
			value: Credential{Type: CredentialBasic, Basic: &BasicCredential{Username: &username, Password: &password}},
		},
		{
			name:  "basic password only",
			value: Credential{Type: CredentialBasic, Basic: &BasicCredential{Password: &password}},
		},
		{
			name:  "basic username wildcard",
			value: Credential{Type: CredentialBasic, Basic: &BasicCredential{AllowAnyUsername: true, Password: &password}},
		},
		{
			name:  "uuid",
			value: Credential{Type: CredentialUUID, UUID: &UUIDCredential{UUID: "00000000-0000-0000-0000-000000000001"}},
		},
		{
			name:  "token",
			value: Credential{Type: CredentialToken, Token: &TokenCredential{Token: "tskey-auth-example"}},
		},
		{
			name:    "missing variant",
			value:   Credential{Type: CredentialBasic},
			wantErr: true,
		},
		{
			name:    "multiple variants",
			value:   Credential{Type: CredentialBasic, Basic: &BasicCredential{Password: &password}, Token: &TokenCredential{Token: "token"}},
			wantErr: true,
		},
		{
			name:    "type mismatch",
			value:   Credential{Type: CredentialUUID, Basic: &BasicCredential{Password: &password}},
			wantErr: true,
		},
		{
			name:    "invalid uuid",
			value:   Credential{Type: CredentialUUID, UUID: &UUIDCredential{UUID: "not-a-uuid"}},
			wantErr: true,
		},
		{
			name:    "empty token",
			value:   Credential{Type: CredentialToken, Token: &TokenCredential{}},
			wantErr: true,
		},
		{
			name:    "empty basic",
			value:   Credential{Type: CredentialBasic, Basic: &BasicCredential{}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.value.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestUserViewDoesNotExposeCredentialSecrets(t *testing.T) {
	username, password := "alice", "secret"
	user := User{
		ID: "user-1", Name: "Alice", Enabled: true, Origin: OriginManual, Usage: UsageBoth,
		Credential: Credential{Type: CredentialBasic, Basic: &BasicCredential{Username: &username, Password: &password}},
	}

	view := user.View()
	if view.Credential.Username != username || !view.Credential.HasUsername || !view.Credential.HasSecret {
		t.Fatalf("view = %+v", view)
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), password) || strings.Contains(string(encoded), "password") {
		t.Fatalf("view JSON leaks secret: %s", encoded)
	}

	for _, credential := range []Credential{
		{Type: CredentialUUID, UUID: &UUIDCredential{UUID: "00000000-0000-0000-0000-000000000001"}},
		{Type: CredentialToken, Token: &TokenCredential{Token: "secret-token"}},
	} {
		view := (User{ID: "id", Origin: OriginManual, Usage: UsageOutbound, Credential: credential}).View()
		if !view.Credential.HasSecret {
			t.Fatalf("credential view did not report secret: %+v", view)
		}
		encoded, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "secret-token") || strings.Contains(string(encoded), "00000000") {
			t.Fatalf("credential view leaked secret: %s", encoded)
		}
	}
}

func TestValidateUsageAndOrigin(t *testing.T) {
	if err := ValidateUsage(UsageInbound); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUsage(Usage("invalid")); err == nil {
		t.Fatal("invalid usage accepted")
	}
	if err := ValidateOrigin(OriginMigrated); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOrigin(Origin("invalid")); err == nil {
		t.Fatal("invalid origin accepted")
	}
}
