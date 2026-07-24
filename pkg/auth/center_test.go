package auth

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	contractuser "github.com/Asutorufa/yuhaiin/pkg/contract/user"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestCenterUsageAndCredentialResolution(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := plainstore.NewUserStore(db.DB())

	password := "top-secret"
	user, err := store.Create(ctx, contractuser.UserWrite{
		Name: "Outbound", Enabled: true, Usage: contractuser.UsageOutbound,
		Credential: contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Password: &password}},
	})
	if err != nil {
		t.Fatal(err)
	}
	center, err := NewCenter(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := center.AuthPassword(password); err == nil {
		t.Fatal("outbound-only user authenticated inbound")
	}
	resolved, err := center.ResolveCredential(user.ID, "shadowsocks")
	if err != nil || resolved.Password != password {
		t.Fatalf("resolved = %+v, err=%v", resolved, err)
	}

	if err := store.Save(ctx, contractuser.User{ID: user.ID, Name: "Outbound", Enabled: false, Origin: contractuser.OriginManual, Usage: contractuser.UsageOutbound, Credential: contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Password: &password}}}, 0); err != nil {
		t.Fatal(err)
	}
	if err := center.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := center.ResolveCredential(user.ID, "shadowsocks"); err == nil {
		t.Fatal("disabled user resolved")
	}
}

func TestCenterInboundCapabilityMatrix(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := plainstore.NewUserStore(db.DB())

	username, password := "alice", "secret"
	passwordOnly := "yuubinsya-secret"
	usernameOnly := "socks4-user"
	create := func(name string, credential contractuser.Credential, usage contractuser.Usage, enabled bool) string {
		t.Helper()
		view, err := store.Create(ctx, contractuser.UserWrite{Name: name, Enabled: enabled, Usage: usage, Credential: credential})
		if err != nil {
			t.Fatal(err)
		}
		return view.ID
	}
	allID := create("Alice", contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Username: &username, Password: &password}}, contractuser.UsageInbound, true)
	passwordID := create("Yuubinsya", contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Password: &passwordOnly}}, contractuser.UsageBoth, true)
	usernameID := create("SOCKS4A", contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Username: &usernameOnly}}, contractuser.UsageInbound, true)
	create("Disabled", contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Username: &username, Password: &password}}, contractuser.UsageBoth, false)
	create("Outbound", contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Username: &username, Password: &password}}, contractuser.UsageOutbound, true)

	center, err := NewCenter(store)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := center.AuthBasic(username, password); err != nil || got.UserID != allID {
		t.Fatalf("AuthBasic() = %+v, err=%v, want user %s", got, err, allID)
	}
	if _, err := center.AuthBasic(username, "wrong"); err != ErrNotFound {
		t.Fatalf("wrong basic credential error = %v, want %v", err, ErrNotFound)
	}
	if got, err := center.AuthUsername(usernameOnly); err != nil || got.UserID != usernameID {
		t.Fatalf("AuthUsername() = %+v, err=%v, want user %s", got, err, usernameID)
	}
	if got, err := center.AuthPassword(passwordOnly); err != nil || got.UserID != passwordID {
		t.Fatalf("AuthPassword() = %+v, err=%v, want user %s", got, err, passwordID)
	}
	if _, err := center.AuthUsername("missing"); err != ErrNotFound {
		t.Fatalf("missing username error = %v", err)
	}
	if !center.HasBasicUsers() || !center.HasUsernameUsers() || !center.HasPasswordUsers() {
		t.Fatalf("capabilities: basic=%v username=%v password=%v", center.HasBasicUsers(), center.HasUsernameUsers(), center.HasPasswordUsers())
	}
	passwords := center.InboundPasswords()
	slices.Sort(passwords)
	if !slices.Equal(passwords, []string{password, passwordOnly}) {
		t.Fatalf("InboundPasswords() = %v", passwords)
	}
}

func TestCenterResolveCredentialMatrix(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := plainstore.NewUserStore(db.DB())

	password := "ss-password"
	username := "proxy-user"
	passwordUser, err := store.Create(ctx, contractuser.UserWrite{
		Name: "Password", Enabled: true, Usage: contractuser.UsageOutbound,
		Credential: contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Password: &password}},
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyUser, err := store.Create(ctx, contractuser.UserWrite{
		Name: "Proxy", Enabled: true, Usage: contractuser.UsageOutbound,
		Credential: contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Username: &username, Password: &password}},
	})
	if err != nil {
		t.Fatal(err)
	}
	uuidUser, err := store.Create(ctx, contractuser.UserWrite{
		Name: "UUID", Enabled: true, Usage: contractuser.UsageOutbound,
		Credential: contractuser.Credential{Type: contractuser.CredentialUUID, UUID: &contractuser.UUIDCredential{UUID: "00000000-0000-0000-0000-000000000001"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	tokenUser, err := store.Create(ctx, contractuser.UserWrite{
		Name: "Token", Enabled: true, Usage: contractuser.UsageOutbound,
		Credential: contractuser.Credential{Type: contractuser.CredentialToken, Token: &contractuser.TokenCredential{Token: "token-value"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	center, err := NewCenter(store)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		userID, protocol string
		want             ResolvedCredential
		wantErr          error
	}{
		{passwordUser.ID, "shadowsocks", ResolvedCredential{UserID: passwordUser.ID, Password: password}, nil},
		{passwordUser.ID, "trojan", ResolvedCredential{UserID: passwordUser.ID, Password: password}, nil},
		{passwordUser.ID, "aead", ResolvedCredential{UserID: passwordUser.ID, Password: password}, nil},
		{proxyUser.ID, "http", ResolvedCredential{UserID: proxyUser.ID, Username: username, Password: password}, nil},
		{uuidUser.ID, "vmess", ResolvedCredential{UserID: uuidUser.ID, UUID: "00000000-0000-0000-0000-000000000001"}, nil},
		{uuidUser.ID, "vless", ResolvedCredential{UserID: uuidUser.ID, UUID: "00000000-0000-0000-0000-000000000001"}, nil},
		{tokenUser.ID, "tailscale", ResolvedCredential{UserID: tokenUser.ID, Token: "token-value"}, nil},
		{passwordUser.ID, "vmess", ResolvedCredential{UserID: passwordUser.ID}, ErrType},
		{uuidUser.ID, "shadowsocks", ResolvedCredential{UserID: uuidUser.ID}, ErrRequired},
		{passwordUser.ID, "unsupported", ResolvedCredential{UserID: passwordUser.ID}, nil},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.userID, tt.protocol), func(t *testing.T) {
			got, err := center.ResolveCredential(tt.userID, tt.protocol)
			if tt.wantErr == nil && tt.protocol != "unsupported" {
				if err != nil || got != tt.want {
					t.Fatalf("ResolveCredential() = %+v, err=%v, want %+v", got, err, tt.want)
				}
				return
			}
			if tt.protocol == "unsupported" {
				if err == nil || got.UserID != tt.userID {
					t.Fatalf("unsupported result = %+v, err=%v", got, err)
				}
				return
			}
			if err == nil || !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want wrapping %v", err, tt.wantErr)
			}
		})
	}
}

func TestCenterBasicCapabilityRequiresBothFields(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := plainstore.NewUserStore(db.DB())
	password := "password-only"
	if _, err := store.Create(ctx, contractuser.UserWrite{
		Name: "Password only", Enabled: true, Usage: contractuser.UsageInbound,
		Credential: contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Password: &password}},
	}); err != nil {
		t.Fatal(err)
	}
	center, err := NewCenter(store)
	if err != nil {
		t.Fatal(err)
	}
	if center.HasBasicUsers() {
		t.Fatal("password-only user incorrectly enables HTTP/SOCKS basic authentication")
	}
	if !center.HasPasswordUsers() {
		t.Fatal("password-only user did not enable password authentication")
	}
}
