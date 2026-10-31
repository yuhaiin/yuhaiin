package auth

import (
	"context"
	"database/sql"
	"slices"
)

// Recheck sensitive role grants inside their write transaction. An in-flight
// request cannot keep permission that its owner lost after HTTP authentication.
// The request's original scopes remain an upper bound, including scoped tokens.
func freshRoleActor(ctx context.Context, tx *sql.Tx, actor Principal) (Principal, error) {
	var base string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM management_users WHERE id=? AND disabled=0 AND credential IS NOT NULL`, actor.UserID).Scan(&base); err != nil {
		return Principal{}, ErrForbidden
	}
	current, err := effectivePermissions(ctx, tx, actor.UserID, base)
	if err != nil {
		return Principal{}, err
	}
	if actor.CredentialID != "" {
		var encoded string
		err := tx.QueryRowContext(ctx, `SELECT c.scopes FROM management_credentials c JOIN management_users u ON u.id=c.user_id WHERE c.id=? AND c.user_id=? AND c.kind=? AND c.revoked=0 AND c.generation=u.generation AND (c.expires_at=0 OR c.expires_at>unixepoch())`, actor.CredentialID, actor.UserID, actor.CredentialType).Scan(&encoded)
		if err != nil {
			return Principal{}, ErrForbidden
		}
	}
	actor.Permissions = slices.DeleteFunc(slices.Clone(actor.Permissions), func(p Permission) bool { return !slices.Contains(current, p) })
	return actor, nil
}

// Store calls from the authenticated HTTP surface cannot administer a stronger
// account by assigning a built-in role, replacing its enrollment or deleting it.
// Local recovery calls intentionally have no HTTP principal and retain their
// separately authorized recovery capability.
func authorizeUserMutation(ctx context.Context, tx *sql.Tx, owner, nextBase string) error {
	actor, authenticated := FromContext(ctx)
	if !authenticated {
		return nil
	}
	actor, err := freshRoleActor(ctx, tx, actor)
	if err != nil {
		return err
	}
	if !actor.Allows(UsersManage) || nextBase != "" && !canGrant(actor, RolePermissions(nextBase)) {
		return ErrForbidden
	}
	if owner != "" {
		var base string
		if err := tx.QueryRowContext(ctx, `SELECT role FROM management_users WHERE id=?`, owner).Scan(&base); err != nil {
			return err
		}
		permissions, err := effectivePermissions(ctx, tx, owner, base)
		if err != nil {
			return err
		}
		if !canGrant(actor, permissions) {
			return ErrForbidden
		}
	}
	return nil
}
