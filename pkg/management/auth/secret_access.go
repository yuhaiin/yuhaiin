package auth

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

const secretAccessHeader = "X-Yuhaiin-Secret-Access"

func (s *Store) authorizeSecretRetrieval(ctx context.Context, actor Principal, resource string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	actor, err = freshRoleActor(ctx, tx, actor)
	if err != nil || !actor.Allows(SecretsRead) {
		return ErrForbidden
	}
	if err := recordEvent(ctx, tx, "secret.retrieval_authorized", actor.UserID, resource); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) secretCapabilities(w http.ResponseWriter, r *http.Request, pattern string, p Principal) (context.Context, bool) {
	reveal := r.Header.Get(secretAccessHeader)
	if reveal != "" && reveal != "reveal" {
		authError(w, http.StatusBadRequest)
		return nil, false
	}
	raw := rawSecretAccess(r, pattern)
	if reveal != "" || raw {
		if !p.Allows(SecretsRead) {
			authError(w, http.StatusForbidden)
			return nil, false
		}
		if err := s.Store.authorizeSecretRetrieval(r.Context(), p, pattern); err != nil {
			authError(w, http.StatusServiceUnavailable)
			return nil, false
		}
	}
	if secretOperation(pattern, "backup.restore") && (!p.Allows(SecretsManage) || !p.Allows(SystemExecute)) {
		authError(w, http.StatusForbidden)
		return nil, false
	}
	if (secretOperation(pattern, "gateway.ca.import") || secretOperation(pattern, "gateway.ca.generate")) && !p.Allows(SecretsManage) {
		authError(w, http.StatusForbidden)
		return nil, false
	}
	// CA material and restore operations bypass typed configuration merging.
	// Record their durable authorization before invoking any side effect.
	if secretOperation(pattern, "gateway.ca.import") || secretOperation(pattern, "gateway.ca.generate") || secretOperation(pattern, "backup.restore") {
		change := secret.Change{Resource: pattern, Secrets: true, Execute: secretOperation(pattern, "backup.restore")}
		if err := s.Store.authorizeSensitiveChange(r.Context(), p, change); err != nil {
			authError(w, http.StatusServiceUnavailable)
			return nil, false
		}
	}
	return secret.WithCapabilities(r.Context(), secret.Capabilities{Security: p.Allows(SecurityWrite), Manage: p.Allows(SecretsManage), Reveal: reveal == "reveal", Execute: p.Allows(SystemExecute), BeforeChange: func(ctx context.Context, change secret.Change) error {
		return s.Store.authorizeSensitiveChange(ctx, p, change)
	}, Revalidate: func(ctx context.Context) (secret.Capabilities, error) {
		proof, kind := credentials(r)
		current, err := s.Store.Authenticate(ctx, proof, kind)
		if err != nil || !current.Allows(s.Permissions[pattern]) {
			return secret.Capabilities{}, ErrForbidden
		}
		return secret.Capabilities{Security: current.Allows(SecurityWrite), Manage: current.Allows(SecretsManage), Execute: current.Allows(SystemExecute)}, nil
	}}), true
}

func rawSecretAccess(r *http.Request, pattern string) bool {
	return strings.HasPrefix(r.URL.Path, "/debug/") || (strings.Contains(pattern, "tools.logs") || strings.HasPrefix(r.URL.Path, "/api/v2/tools/logs") || r.URL.Path == "/api/v2/logs") || secretOperation(pattern, "backup.run")
}

// The private audit records authorization before writing another SQLite store.
// This is durable intent, never a claim that the separate configuration commit
// succeeded. Unified configuration history supplies final commit outcomes.
func (s *Store) authorizeSensitiveChange(ctx context.Context, actor Principal, change secret.Change) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	actor, err = freshRoleActor(ctx, tx, actor)
	if err != nil || change.Secrets && !actor.Allows(SecretsManage) || change.Execute && !actor.Allows(SystemExecute) || change.Security && !actor.Allows(SecurityWrite) {
		return ErrForbidden
	}
	encoded, err := json.Marshal(change)
	if err != nil {
		return err
	}
	info, _ := ctx.Value(auditKey{}).(auditInfo)
	info.changes = string(encoded)
	ctx = context.WithValue(ctx, auditKey{}, info)
	if err := recordEvent(ctx, tx, "configuration.sensitive_change_authorized", actor.UserID, change.Resource); err != nil {
		return err
	}
	return tx.Commit()
}

func secretOperation(pattern, endpoint string) bool {
	return strings.HasSuffix(pattern, "/rpc/"+endpoint) || strings.HasSuffix(pattern, "/api/v2/"+strings.ReplaceAll(endpoint, ".", "/"))
}
