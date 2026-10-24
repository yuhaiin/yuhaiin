package auth

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"
	"uuid"
)

type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	Revision    uint64       `json:"revision"`
	BuiltIn     bool         `json:"builtIn"`
}

type RoleAssignment struct {
	UserID      string       `json:"userId"`
	BaseRole    string       `json:"baseRole"`
	Disabled    bool         `json:"disabled"`
	Enrolled    bool         `json:"enrolled"`
	RoleIDs     []string     `json:"roleIds"`
	Revision    uint64       `json:"revision"`
	Permissions []Permission `json:"permissions"`
}

type roleQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// Effective permissions are resolved on management requests, never forwarding.
// Unknown durable permissions fail closed; tokens additionally intersect their
// immutable issuance scopes in Authenticate.
func effectivePermissions(ctx context.Context, query roleQuery, owner, base string) ([]Permission, error) {
	permissions := RolePermissions(base)
	if len(permissions) == 0 {
		return nil, ErrInvalid
	}
	rows, err := query.QueryContext(ctx, `SELECT r.permissions FROM management_roles r JOIN management_user_roles u ON u.role_id=r.id WHERE u.user_id=? ORDER BY r.id`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, err
		}
		var custom []Permission
		if err := json.Unmarshal([]byte(encoded), &custom); err != nil {
			return nil, err
		}
		for _, permission := range custom {
			if !slices.Contains(allPermissions, permission) {
				return nil, ErrInvalid
			}
			permissions = append(permissions, permission)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.Sort(permissions)
	return slices.Compact(permissions), nil
}

func (s *Store) Roles(ctx context.Context) ([]Role, error) {
	out := []Role{}
	for _, id := range []string{Admin, ReadOnly, NoManagement} {
		out = append(out, Role{ID: id, Name: id, Permissions: RolePermissions(id), BuiltIn: true})
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,description,permissions,revision FROM management_roles ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var role Role
		var encoded string
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &encoded, &role.Revision); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(encoded), &role.Permissions); err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func canGrant(actor Principal, permissions []Permission) bool {
	for _, permission := range permissions {
		if !actor.Allows(permission) {
			return false
		}
	}
	return true
}

func (s *Store) SaveRole(ctx context.Context, actor Principal, role Role) (Role, error) {
	if !actor.Allows(RolesWrite) || !canGrant(actor, role.Permissions) {
		return Role{}, ErrForbidden
	}
	role.Name = strings.TrimSpace(role.Name)
	if role.BuiltIn || role.ID == Admin || role.ID == ReadOnly || role.ID == NoManagement || len(role.ID) > 128 || role.Name == "" || len(role.Name) > 128 || !utf8.ValidString(role.Name) || len(role.Description) > 2048 || !utf8.ValidString(role.Description) || len(role.Permissions) > len(allPermissions) || role.Revision >= 1<<53-1 {
		return Role{}, ErrInvalid
	}
	for _, p := range role.Permissions {
		if !slices.Contains(allPermissions, p) {
			return Role{}, ErrInvalid
		}
	}
	role.Permissions = slices.Clone(role.Permissions)
	slices.Sort(role.Permissions)
	role.Permissions = slices.Compact(role.Permissions)
	if role.Permissions == nil {
		role.Permissions = []Permission{}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Role{}, err
	}
	defer func() { _ = tx.Rollback() }()
	actor, err = freshRoleActor(ctx, tx, actor)
	if err != nil {
		return Role{}, err
	}
	if !actor.Allows(RolesWrite) {
		return Role{}, ErrForbidden
	}

	if !canGrant(actor, role.Permissions) {
		return Role{}, ErrForbidden
	}
	var before *Role
	if role.ID == "" {
		if role.Revision != 0 {
			return Role{}, ErrConflict
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM management_roles`).Scan(&count); err != nil {
			return Role{}, err
		}
		if count >= 128 {
			return Role{}, ErrConflict
		}
		role.ID = uuid.New().String()
	} else {
		prior, err := loadRole(ctx, tx, role.ID)
		if err != nil {
			return Role{}, err
		}
		if !canGrant(actor, prior.Permissions) {
			return Role{}, ErrForbidden
		}
		if prior.Revision != role.Revision {
			return Role{}, ErrConflict
		}
		before = &prior
	}
	role.Revision++
	encoded, err := json.Marshal(role.Permissions)
	if err != nil {
		return Role{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO management_roles(id,name,description,permissions,revision) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,permissions=excluded.permissions,revision=excluded.revision`, role.ID, role.Name, role.Description, string(encoded), role.Revision); err != nil {
		return Role{}, ErrConflict
	}
	ctx, err = roleAuditContext(ctx, before, role)
	if err != nil {
		return Role{}, err
	}
	if err := recordEvent(ctx, tx, "role.updated", actor.UserID, role.ID); err != nil {
		return Role{}, err
	}
	return role, tx.Commit()
}

func loadRole(ctx context.Context, tx *sql.Tx, id string) (Role, error) {
	var role Role
	var encoded string
	err := tx.QueryRowContext(ctx, `SELECT id,name,description,permissions,revision FROM management_roles WHERE id=?`, id).Scan(&role.ID, &role.Name, &role.Description, &encoded, &role.Revision)
	if err == nil {
		err = json.Unmarshal([]byte(encoded), &role.Permissions)
	}
	return role, err
}

func roleAuditContext(ctx context.Context, before, after any) (context.Context, error) {
	encoded, err := json.Marshal(struct {
		Before any `json:"before"`
		After  any `json:"after"`
	}{before, after})
	info, _ := ctx.Value(auditKey{}).(auditInfo)
	info.changes = string(encoded)
	return context.WithValue(ctx, auditKey{}, info), err
}

func (s *Store) DeleteRole(ctx context.Context, actor Principal, id string, revision uint64) error {
	if !actor.Allows(RolesWrite) {
		return ErrForbidden
	}
	if id == Admin || id == ReadOnly || id == NoManagement {
		return ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	actor, err = freshRoleActor(ctx, tx, actor)
	if err != nil {
		return err
	}
	if !actor.Allows(RolesWrite) {
		return ErrForbidden
	}

	role, err := loadRole(ctx, tx, id)
	if err != nil {
		return err
	}
	if !canGrant(actor, role.Permissions) {
		return ErrForbidden
	}
	if role.Revision != revision {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_roles WHERE id=?`, id); err != nil {
		return ErrConflict
	}
	ctx, err = roleAuditContext(ctx, role, nil)
	if err != nil {
		return err
	}
	if err := recordEvent(ctx, tx, "role.deleted", actor.UserID, id); err != nil {
		return err
	}
	return tx.Commit()
}

func roleAssignment(ctx context.Context, tx *sql.Tx, owner string) (RoleAssignment, error) {
	out := RoleAssignment{UserID: owner, RoleIDs: []string{}}
	if err := tx.QueryRowContext(ctx, `SELECT role,disabled,credential IS NOT NULL FROM management_users WHERE id=?`, owner).Scan(&out.BaseRole, &out.Disabled, &out.Enrolled); err != nil {
		return out, err
	}
	err := tx.QueryRowContext(ctx, `SELECT revision FROM management_role_assignments WHERE user_id=?`, owner).Scan(&out.Revision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT role_id FROM management_user_roles WHERE user_id=? ORDER BY role_id`, owner)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return out, err
		}
		out.RoleIDs = append(out.RoleIDs, id)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return out, err
	}
	out.Permissions, err = effectivePermissions(ctx, tx, owner, out.BaseRole)
	if out.Disabled || !out.Enrolled {
		out.Permissions = []Permission{}
	}
	return out, err
}

func (s *Store) RoleAssignment(ctx context.Context, actor Principal, owner string) (RoleAssignment, error) {
	if owner != actor.UserID && !actor.Allows(RolesRead) {
		return RoleAssignment{}, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RoleAssignment{}, err
	}
	defer func() { _ = tx.Rollback() }()
	return roleAssignment(ctx, tx, owner)
}

func (s *Store) AssignRoles(ctx context.Context, actor Principal, owner string, revision uint64, ids []string) (RoleAssignment, error) {
	if !actor.Allows(RolesWrite) || !actor.Allows(UsersManage) {
		return RoleAssignment{}, ErrForbidden
	}
	if len(ids) > 32 || revision >= 1<<53-1 {
		return RoleAssignment{}, ErrInvalid
	}
	ids = slices.Clone(ids)
	slices.Sort(ids)
	if len(slices.Compact(slices.Clone(ids))) != len(ids) {
		return RoleAssignment{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RoleAssignment{}, err
	}
	defer func() { _ = tx.Rollback() }()
	actor, err = freshRoleActor(ctx, tx, actor)
	if err != nil {
		return RoleAssignment{}, err
	}
	if !actor.Allows(RolesWrite) {
		return RoleAssignment{}, ErrForbidden
	}

	if !actor.Allows(UsersManage) {
		return RoleAssignment{}, ErrForbidden
	}
	before, err := roleAssignment(ctx, tx, owner)
	if err != nil {
		return RoleAssignment{}, err
	}
	declared, err := effectivePermissions(ctx, tx, owner, before.BaseRole)
	if err != nil {
		return RoleAssignment{}, err
	}
	if !canGrant(actor, declared) {
		return RoleAssignment{}, ErrForbidden
	}
	if before.Revision != revision {
		return RoleAssignment{}, ErrConflict
	}
	for _, id := range ids {
		role, err := loadRole(ctx, tx, id)
		if err != nil {
			return RoleAssignment{}, ErrInvalid
		}
		if !canGrant(actor, role.Permissions) {
			return RoleAssignment{}, ErrForbidden
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_user_roles WHERE user_id=?`, owner); err != nil {
		return RoleAssignment{}, err
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `INSERT INTO management_user_roles(user_id,role_id) VALUES(?,?)`, owner, id); err != nil {
			return RoleAssignment{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO management_role_assignments(user_id,revision) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET revision=excluded.revision`, owner, revision+1); err != nil {
		return RoleAssignment{}, err
	}
	after, err := roleAssignment(ctx, tx, owner)
	if err != nil {
		return RoleAssignment{}, err
	}
	ctx, err = roleAuditContext(ctx, before, after)
	if err != nil {
		return RoleAssignment{}, err
	}
	if err := recordEvent(ctx, tx, "role.assigned", actor.UserID, owner); err != nil {
		return RoleAssignment{}, err
	}
	return after, tx.Commit()
}
