package auth

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"uuid"
)

type configurationFixture struct {
	s       *Store
	server  *Server
	handler http.Handler
	admin   User
	proof   string
}

func configurationTestServer(t *testing.T) *configurationFixture {
	t.Helper()
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	proxy, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	access, err := NewAccessPolicies(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := NewResourcePolicies(t.Context(), s, proxy, access.Controller)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resources.Close(); _ = access.Controller.Close(); _ = proxy.Close() })
	server := &Server{Store: s, Proxy: proxy, Access: access, Resources: resources}
	mux := http.NewServeMux()
	server.Register(mux)
	issued, err := s.IssueToken(t.Context(), principal(admin), admin.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return &configurationFixture{s: s, server: server, handler: server.Wrap(mux), admin: admin, proof: issued.Secret}
}
func (f *configurationFixture) request(t *testing.T, method, path, proof string, body any, code int) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, "http://localhost/api/v2/auth"+path, bytes.NewReader(data))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Authorization", "Bearer "+proof)
	if len(proof) > 0 && proof[0] == 's' {
		r.Header.Set("Authorization", "Session "+proof[1:])
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != code {
		t.Fatalf("%s %s=%d want=%d body=%s", method, path, w.Code, code, w.Body.String())
	}
	return w
}
func parseConfigurationResponse(t *testing.T, w *httptest.ResponseRecorder) configurationChangeResponse {
	t.Helper()
	var out configurationChangeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func stageBody(kind, id, action string, payload any) any {
	return struct {
		Store   string `json:"store"`
		Kind    string `json:"kind"`
		ID      string `json:"resourceId"`
		Action  string `json:"action"`
		Payload any    `json:"payload"`
	}{"identity", kind, id, action, payload}
}
func (f *configurationFixture) commit(t *testing.T, change configurationChangeResponse) configurationChangeResponse {
	return parseConfigurationResponse(t, f.request(t, "POST", "/changes/identity/"+change.ID+"/commit", f.proof, struct{}{}, 200))
}
func TestConfigurationGroupStageActivationAndRollback(t *testing.T) {
	f := configurationTestServer(t)
	member := testUser(t, f.s, "member", NoManagement)
	staged := parseConfigurationResponse(t, f.request(t, "POST", "/changes", f.proof, stageBody("group", "", "save", GroupRequest{Name: "staged group", Members: []string{member.ID}}), 200))
	if staged.State != "staged" || staged.ResourceID == "" || f.server.Proxy.GroupRevision(staged.ResourceID) != 0 {
		t.Fatalf("staged=%+v", staged)
	}
	groups, err := f.s.Groups(t.Context())
	if err != nil || len(groups) != 0 {
		t.Fatalf("staged groups=%+v err=%v", groups, err)
	}
	f.request(t, "POST", "/changes/identity/"+staged.ID+"/validate", f.proof, struct{}{}, 200)
	committed := f.commit(t, staged)
	if committed.State != "committed" || committed.Activation != "active" || f.server.Proxy.GroupRevision(staged.ResourceID) != 1 {
		t.Fatalf("committed=%+v", committed)
	}
	group, err := f.s.Group(t.Context(), staged.ResourceID)
	if err != nil || len(group.Members) != 1 {
		t.Fatalf("group=%+v err=%v", group, err)
	}
	rollback := parseConfigurationResponse(t, f.request(t, "POST", "/changes/identity/"+committed.ID+"/rollback", f.proof, struct{}{}, 200))
	if rollback.Origin != "rollback" || rollback.RollbackOf != committed.ID {
		t.Fatalf("rollback=%+v", rollback)
	}
	removed := f.commit(t, rollback)
	group, err = f.s.Group(t.Context(), staged.ResourceID)
	if err != nil || !group.Deleted || group.Revision != 2 || removed.Activation != "active" {
		t.Fatalf("removed=%+v group=%+v err=%v", removed, group, err)
	}
	restore := parseConfigurationResponse(t, f.request(t, "POST", "/changes/identity/"+removed.ID+"/rollback", f.proof, struct{}{}, 200))
	restored := f.commit(t, restore)
	group, err = f.s.Group(t.Context(), staged.ResourceID)
	if err != nil || group.Deleted || group.Revision != 3 || len(group.Members) != 1 || restored.Activation != "active" {
		t.Fatalf("restored=%+v group=%+v err=%v", restored, group, err)
	}
}
func TestConfigurationHistoryFailureAndRevisionConflict(t *testing.T) {
	f := configurationTestServer(t)
	role, err := f.s.SaveRole(t.Context(), principal(f.admin), Role{Name: "operator", Permissions: []Permission{NodesRead}})
	if err != nil {
		t.Fatal(err)
	}
	desired := role
	desired.Name = "staged operator"
	staged := parseConfigurationResponse(t, f.request(t, "POST", "/changes", f.proof, stageBody("role", role.ID, "save", desired), 200))
	role.Name = "concurrent"
	role, err = f.s.SaveRole(t.Context(), principal(f.admin), role)
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, "POST", "/changes/identity/"+staged.ID+"/commit", f.proof, struct{}{}, 409)
	desired = role
	desired.Name = "must roll back"
	second := parseConfigurationResponse(t, f.request(t, "POST", "/changes", f.proof, stageBody("role", role.ID, "save", desired), 200))
	if _, err = f.s.db.ExecContext(t.Context(), `CREATE TRIGGER break_configuration_history BEFORE UPDATE ON configuration_changes BEGIN SELECT RAISE(FAIL,'history unavailable');END`); err != nil {
		t.Fatal(err)
	}
	f.request(t, "POST", "/changes/identity/"+second.ID+"/commit", f.proof, struct{}{}, 500)
	tx, err := f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	current, err := loadRole(t.Context(), tx, role.ID)
	_ = tx.Rollback()
	if err != nil || current.Name != "concurrent" || current.Revision != role.Revision {
		t.Fatalf("partial policy=%+v err=%v", current, err)
	}
	entry, err := f.server.Changes.identity.Get(t.Context(), second.ID)
	if err != nil || entry.State != "staged" {
		t.Fatalf("failed history=%+v err=%v", entry, err)
	}
}
func TestConfigurationKindVisibilityAndScopeRevalidation(t *testing.T) {
	f := configurationTestServer(t)
	role, err := f.s.SaveRole(t.Context(), principal(f.admin), Role{Name: "network reader", Permissions: []Permission{NodesRead}})
	if err != nil {
		t.Fatal(err)
	}
	staged := parseConfigurationResponse(t, f.request(t, "POST", "/changes", f.proof, stageBody("role", role.ID, "save", role), 200))
	limited, err := f.s.IssueToken(t.Context(), principal(f.admin), f.admin.ID, []Permission{ConfigurationRead, ConfigurationWrite, NodesRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	list := f.request(t, "GET", "/changes", limited.Secret, nil, 200)
	if bytes.Contains(list.Body.Bytes(), []byte(staged.ID)) {
		t.Fatal("history ignored resource read permission")
	}
	f.request(t, "GET", "/changes/identity/"+staged.ID, limited.Secret, nil, 403)
	f.request(t, "POST", "/changes/identity/"+staged.ID+"/commit", limited.Secret, struct{}{}, 403)
	if err = f.s.Revoke(t.Context(), principal(f.admin), limited.ID); err != nil {
		t.Fatal(err)
	}
	f.request(t, "POST", "/changes", limited.Secret, stageBody("role", role.ID, "save", role), 401)
}
func TestConfigurationAllowsAuthorizedSelfDemotion(t *testing.T) {
	f := configurationTestServer(t)
	operator := testUser(t, f.s, "operator", NoManagement)
	role, err := f.s.SaveRole(t.Context(), principal(f.admin), Role{Name: "policy operator", Permissions: []Permission{ConfigurationRead, ConfigurationWrite, RolesRead, RolesWrite, NodesRead}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.AssignRoles(t.Context(), principal(f.admin), operator.ID, 0, []string{role.ID}); err != nil {
		t.Fatal(err)
	}
	token, err := f.s.IssueToken(t.Context(), principal(f.admin), operator.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	desired := role
	desired.Permissions = []Permission{NodesRead}
	staged := parseConfigurationResponse(t, f.request(t, "POST", "/changes", token.Secret, stageBody("role", role.ID, "save", desired), 200))
	f.request(t, "POST", "/changes/identity/"+staged.ID+"/commit", token.Secret, struct{}{}, 200)
	p, err := f.s.Authenticate(t.Context(), token.Secret, "token")
	if err != nil || p.Allows(RolesWrite) || p.Allows(ConfigurationWrite) || !p.Allows(NodesRead) {
		t.Fatalf("self demotion=%+v err=%v", p, err)
	}
}
func TestConfigurationOIDCRevocationAndPrivateHistory(t *testing.T) {
	f := configurationTestServer(t)
	id := "oidc-" + uuid.New().String()
	provider := OAuthProvider{Provider: id, Name: "enterprise", Issuer: "https://idp.example", ClientID: "client", ClientSecret: "private-provider-proof", RedirectURL: "https://controller.example/api/v2/auth/oauth/" + id + "/callback"}
	if err := f.s.SaveOAuthProvider(t.Context(), f.admin.ID, provider); err != nil {
		t.Fatal(err)
	}
	saved, err := f.s.oauthProvider(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := issueCredential(t.Context(), tx, f.admin.ID, "session", nil, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err = saveSessionInfo(t.Context(), tx, session.ID, sessionInfo{Method: id}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	desired := publicOAuthProvider(saved)
	desired.Enabled = new(false)
	staged := parseConfigurationResponse(t, f.request(t, "POST", "/changes", "s"+session.Secret, stageBody("oidc-provider", id, "save", desired), 200))
	if _, err = f.s.Authenticate(t.Context(), session.Secret, "session"); err != nil {
		t.Fatal("staging revoked session", err)
	}
	committed := parseConfigurationResponse(t, f.request(t, "POST", "/changes/identity/"+staged.ID+"/commit", "s"+session.Secret, struct{}{}, 200))
	encoded, _ := json.Marshal(committed)
	if bytes.Contains(encoded, []byte("private-provider-proof")) {
		t.Fatal("journal returned private client secret")
	}
	if _, err = f.s.Authenticate(t.Context(), session.Secret, "session"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("self provider disable retained session: %v", err)
	}
	if err = f.s.DeleteOAuthProvider(t.Context(), f.admin.ID, id); err != nil {
		t.Fatal(err)
	}
	provider.Revision = 0
	if err = f.s.SaveOAuthProvider(t.Context(), f.admin.ID, provider); err != nil {
		t.Fatal(err)
	}
	recreated, err := f.s.oauthProvider(t.Context(), id)
	if err != nil || recreated.Revision <= saved.Revision+1 {
		t.Fatalf("provider revision reused old=%d recreated=%d err=%v", saved.Revision, recreated.Revision, err)
	}
}
func TestConfigurationValidationDoesNotPublishPolicies(t *testing.T) {
	f := configurationTestServer(t)
	before := f.server.Access.Controller.Config()
	body := before
	body.Enabled = true
	body.DefaultAction = "deny"
	response := f.request(t, "POST", "/changes", f.proof, stageBody("access-policy", "traffic-access", "save", body), 200)
	staged := parseConfigurationResponse(t, response)
	if f.server.Access.Controller.Config().Revision != before.Revision {
		t.Fatal("staging changed active access policy")
	}
	if _, err := f.server.Changes.identity.Get(t.Context(), staged.ID); err != nil {
		t.Fatal(err)
	}
	f.commit(t, staged)
	if f.server.Access.Controller.Config().Revision != before.Revision+1 {
		t.Fatal("committed policy did not activate")
	}
}

func TestConfigurationResourceStagingKeepsRuntimeAndQuotaState(t *testing.T) {
	f := configurationTestServer(t)
	before := f.server.Resources.Control.ResourceConfig()
	status := f.server.Resources.Status()
	body := before
	body.Enabled = true
	body.DefaultUser.Quotas = []resource.Quota{{ID: "daily", Period: "daily", Combined: "1048576", Action: "block_new"}}
	// Invalid references must fail before creating a draft.
	invalid := body
	invalid.Users = []resource.UserPolicy{{UserID: "missing"}}
	f.request(t, "POST", "/changes", f.proof, stageBody("resource-policy", "resources", "save", invalid), 400)
	staged := parseConfigurationResponse(t, f.request(t, "POST", "/changes", f.proof, stageBody("resource-policy", "resources", "save", body), 200))
	for range 4 {
		f.request(t, "POST", "/changes/identity/"+staged.ID+"/validate", f.proof, struct{}{}, 200)
	}
	if f.server.Resources.Control.ResourceConfig().Revision != before.Revision || f.server.Resources.Status().Windows != status.Windows {
		t.Fatal("validation changed active policy or retained quota windows")
	}
	f.commit(t, staged)
	if f.server.Resources.Control.ResourceConfig().Revision != before.Revision+1 {
		t.Fatal("resource commit was not activated")
	}
}
