package auth

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func roleTestSession(t *testing.T, s *Store, u User) IssuedCredential {
	t.Helper()
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	issued, err := issueCredential(t.Context(), tx, u.ID, "session", nil, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return issued
}

func TestCustomRolesComposeAndTokensNeverGainScopes(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	user := testUser(t, s, "operator", NoManagement)
	a := principal(admin)
	role, err := s.SaveRole(t.Context(), a, Role{Name: "Network Operator", Permissions: []Permission{NodesRead, NodesWrite, TokensOwn}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AssignRoles(t.Context(), a, user.ID, 0, []string{role.ID}); err != nil {
		t.Fatal(err)
	}
	session := roleTestSession(t, s, user)
	p, err := s.Authenticate(t.Context(), session.Secret, "session")
	if err != nil || !p.Allows(NodesWrite) || !p.Allows(UsageOwn) {
		t.Fatal("custom role did not compose with proxy-only identity", p, err)
	}
	token, err := s.IssueToken(t.Context(), p, user.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	role.Permissions = append(role.Permissions, RoutesWrite)
	role, err = s.SaveRole(t.Context(), a, role)
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.Authenticate(t.Context(), session.Secret, "session")
	if err != nil || !current.Allows(RoutesWrite) {
		t.Fatal("session did not observe role promotion", err)
	}
	bounded, err := s.Authenticate(t.Context(), token.Secret, "token")
	if err != nil || bounded.Allows(RoutesWrite) || !bounded.Allows(NodesWrite) {
		t.Fatal("old token expanded", bounded, err)
	}
	role.Permissions = []Permission{NodesRead, TokensOwn}
	if _, err := s.SaveRole(t.Context(), a, role); err != nil {
		t.Fatal(err)
	}
	bounded, err = s.Authenticate(t.Context(), token.Secret, "token")
	if err != nil || bounded.Allows(NodesWrite) {
		t.Fatal("token retained removed owner permissions", bounded, err)
	}
	if _, err := s.RotateToken(t.Context(), current, token.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("rotation resurrected a removed permission", err)
	}
	if _, err := s.RoleAssignment(t.Context(), principal(user), admin.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("own permission inspection crossed owner boundary", err)
	}
	assignment, err := s.RoleAssignment(t.Context(), principal(user), user.ID)
	if err != nil || !slices.Equal(assignment.RoleIDs, []string{role.ID}) || slices.Contains(assignment.Permissions, NodesWrite) {
		t.Fatal(assignment, err)
	}
}

func TestRoleReferencesConflictsAndAuditRollback(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	user := testUser(t, s, "operator", NoManagement)
	a := principal(admin)
	role, err := s.SaveRole(t.Context(), a, Role{Name: "Auditor", Permissions: []Permission{SecurityRead}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AssignRoles(t.Context(), a, user.ID, 0, []string{role.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRole(t.Context(), a, role.ID, role.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("assigned role deleted", err)
	}
	if _, err := s.AssignRoles(t.Context(), a, user.ID, 0, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("stale assignment accepted", err)
	}
	if _, err := s.AssignRoles(t.Context(), a, user.ID, 1, []string{"unknown"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown role assigned", err)
	}
	if _, err := s.AssignRoles(t.Context(), a, user.ID, 1, []string{role.ID, role.ID}); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate assignment accepted", err)
	}
	if _, err := s.db.ExecContext(t.Context(), `CREATE TRIGGER fail_role_audit BEFORE INSERT ON management_security_events BEGIN SELECT RAISE(ABORT,'audit unavailable');END`); err != nil {
		t.Fatal(err)
	}
	role.Name = "Uncommitted"
	if _, err := s.SaveRole(t.Context(), a, role); err == nil {
		t.Fatal("role persisted without its change audit")
	}
	if _, err := s.AssignRoles(t.Context(), a, user.ID, 1, nil); err == nil {
		t.Fatal("assignment persisted without its audit")
	}
	if _, err := s.db.ExecContext(t.Context(), `DROP TRIGGER fail_role_audit`); err != nil {
		t.Fatal(err)
	}
	roles, err := s.Roles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		if r.ID == role.ID && (r.Name != "Auditor" || r.Revision != 1) {
			t.Fatal("failed role edit changed state", r)
		}
	}
	assignment, err := s.RoleAssignment(t.Context(), a, user.ID)
	if err != nil || assignment.Revision != 1 || len(assignment.RoleIDs) != 1 {
		t.Fatal("failed assignment changed state", assignment, err)
	}
	if _, err := s.AssignRoles(t.Context(), a, user.ID, 1, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRole(t.Context(), a, role.ID, role.Revision); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRole(t.Context(), a, Admin, 0); !errors.Is(err, ErrForbidden) {
		t.Fatal("built-in administrator role deleted", err)
	}
}

func TestDelegatedRoleManagerCannotEscalateOrResetStrongerUsers(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	operator := testUser(t, s, "operator", NoManagement)
	u := testUser(t, s, "proxy", NoManagement)
	a := principal(admin)
	role, err := s.SaveRole(t.Context(), a, Role{Name: "Helpdesk", Permissions: []Permission{RolesRead, RolesWrite, UsersManage, NodesRead}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AssignRoles(t.Context(), a, operator.ID, 0, []string{role.ID}); err != nil {
		t.Fatal(err)
	}
	session := roleTestSession(t, s, operator)
	p, err := s.Authenticate(t.Context(), session.Secret, "session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveRole(t.Context(), p, Role{Name: "Escalation", Permissions: []Permission{NodesWrite}}); !errors.Is(err, ErrForbidden) {
		t.Fatal("custom role escalation", err)
	}
	ctx := WithPrincipal(t.Context(), p)
	if _, _, err := s.CreateUser(ctx, p.UserID, "backdoor", Admin, false); !errors.Is(err, ErrForbidden) {
		t.Fatal("built-in role escalation", err)
	}
	if err := s.UpdateUser(ctx, p.UserID, u.ID, u.Login, Admin, false); !errors.Is(err, ErrForbidden) {
		t.Fatal("promoted another account", err)
	}
	if _, err := s.ResetEnrollment(ctx, p.UserID, admin.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("reset a stronger account", err)
	}
	if err := s.DeleteUser(ctx, p.UserID, admin.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("deleted stronger account", err)
	}
	if _, _, err := s.CreateUser(ctx, p.UserID, "allowed-proxy", NoManagement, false); err != nil {
		t.Fatal("bounded helpdesk creation failed", err)
	}
	if _, err := s.AssignRoles(t.Context(), a, operator.ID, 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveRole(t.Context(), p, Role{Name: "Stale request", Permissions: []Permission{NodesRead}}); !errors.Is(err, ErrForbidden) {
		t.Fatal("stale actor kept removed privileges", err)
	}
}
