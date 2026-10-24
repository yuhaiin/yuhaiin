package auth

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"
)

// Traffic groups do not confer management permissions. Members and revisions
// are replaced in the same transaction as the durable management audit.
type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Members     []string `json:"members"`
	Revision    uint64   `json:"revision"`
	Deleted     bool     `json:"deleted"`
	CreatedAt   int64    `json:"createdAt"`
	UpdatedAt   int64    `json:"updatedAt"`
}

type GroupRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Members     []string `json:"members"`
	Revision    uint64   `json:"revision"`
}

func (s *Store) Groups(ctx context.Context) ([]Group, error) {
	return readGroups(ctx, s.db, "")
}

type groupReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func readGroups(ctx context.Context, db groupReader, id string) ([]Group, error) {
	rows, err := db.QueryContext(ctx, `SELECT g.id,g.name,g.description,g.revision,g.deleted,g.created_at,g.updated_at,m.user_id
		FROM traffic_groups g LEFT JOIN traffic_group_members m ON g.id=m.group_id
		WHERE (?='' AND g.deleted=0 OR g.id=?) ORDER BY g.id,m.user_id`, id, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []Group{}
	for rows.Next() {
		var g Group
		var member sql.NullString
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Revision, &g.Deleted, &g.CreatedAt, &g.UpdatedAt, &member); err != nil {
			return nil, err
		}
		if len(groups) == 0 || groups[len(groups)-1].ID != g.ID {
			g.Members = []string{}
			groups = append(groups, g)
		}
		if member.Valid {
			groups[len(groups)-1].Members = append(groups[len(groups)-1].Members, member.String)
		}
	}
	return groups, rows.Err()
}

func (s *Store) Group(ctx context.Context, id string) (Group, error) {
	groups, err := readGroups(ctx, s.db, id)
	if err != nil {
		return Group{}, err
	}
	if len(groups) != 1 || id == "" {
		return Group{}, sql.ErrNoRows
	}
	return groups[0], nil
}

func (s *Store) SaveGroup(ctx context.Context, actor Principal, id string, request GroupRequest) (Group, error) {
	if !actor.Allows(UsersManage) {
		return Group{}, ErrForbidden
	}
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 128 || len(request.Description) > 2048 || len(request.Members) > 1024 || request.Revision >= (1<<53)-1 {
		return Group{}, ErrInvalid
	}
	members := slices.Clone(request.Members)
	if members == nil {
		members = []string{}
	}
	slices.Sort(members)
	if len(slices.Compact(slices.Clone(members))) != len(members) {
		return Group{}, ErrInvalid
	}
	tx, err := configchange.Begin(ctx, s.db, "group")
	if err != nil {
		return Group{}, err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().Unix()
	g := Group{ID: id, Name: request.Name, Description: request.Description, Members: members, Revision: 1, CreatedAt: now, UpdatedAt: now}
	var before *Group
	event := "group.created"
	if id == "" {
		if request.Revision != 0 {
			return Group{}, ErrConflict
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM traffic_groups`).Scan(&count); err != nil {
			return Group{}, err
		}
		// Tombstones preserve immutable policy references; bound their retention
		// as well as active groups rather than silently reusing an old identity.
		if count >= 4096 {
			return Group{}, ErrConflict
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM traffic_groups WHERE deleted=0`).Scan(&count); err != nil {
			return Group{}, err
		}
		if count >= 1024 {
			return Group{}, ErrConflict
		}
		g.ID = configchange.NewResourceID(ctx, uuid.New().String())
		if _, err := tx.ExecContext(ctx, `INSERT INTO traffic_groups(id,name,description,created_at,updated_at) VALUES(?,?,?,?,?)`, g.ID, g.Name, g.Description, now, now); err != nil {
			return Group{}, ErrConflict
		}
	} else {
		groups, err := readGroups(ctx, tx, id)
		if err != nil {
			return Group{}, err
		}
		if len(groups) != 1 {
			return Group{}, sql.ErrNoRows
		}
		before = &groups[0]
		if before.Deleted && !configchange.Restoring(ctx) || before.Revision != request.Revision {
			return Group{}, ErrConflict
		}
		if before.Deleted {
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM traffic_groups WHERE deleted=0`).Scan(&count); err != nil {
				return Group{}, err
			}
			if count >= 1024 {
				return Group{}, ErrConflict
			}
		}
		g.Revision, g.CreatedAt = before.Revision+1, before.CreatedAt
		if _, err := tx.ExecContext(ctx, `UPDATE traffic_groups SET deleted=0,name=?,description=?,revision=?,updated_at=? WHERE id=?`, g.Name, g.Description, g.Revision, now, id); err != nil {
			return Group{}, ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_group_members WHERE group_id=?`, id); err != nil {
			return Group{}, err
		}
		event = "group.updated"
	}
	for _, member := range members {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM traffic_group_members WHERE user_id=?`, member).Scan(&count); err != nil {
			return Group{}, err
		}
		if count >= 64 {
			return Group{}, ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO traffic_group_members(group_id,user_id) VALUES(?,?)`, g.ID, member); err != nil {
			return Group{}, ErrInvalid
		}
	}
	ctx, err = groupAuditContext(ctx, before, &g)
	if err != nil {
		return Group{}, err
	}
	if err := recordEvent(ctx, tx, event, actor.UserID, g.ID); err != nil {
		return Group{}, err
	}
	if err := configchange.RecordValues(ctx, s.db, tx, "group", g.ID, g.Revision, before, g, before, g); err != nil {
		return Group{}, err
	}
	return g, configchange.Commit(ctx, tx)
}

func groupAuditContext(ctx context.Context, before, after *Group) (context.Context, error) {
	changes, err := json.Marshal(struct {
		Before *Group `json:"before"`
		After  *Group `json:"after"`
	}{before, after})
	info, _ := ctx.Value(auditKey{}).(auditInfo)
	info.changes = string(changes)
	if after != nil {
		info.policyRevision = strconv.FormatUint(after.Revision, 10)
	} else if before != nil {
		info.policyRevision = strconv.FormatUint(before.Revision+1, 10)
	}
	return context.WithValue(ctx, auditKey{}, info), err
}

func (s *Store) DeleteGroup(ctx context.Context, actor Principal, id string, revision uint64) error {
	if !actor.Allows(UsersManage) {
		return ErrForbidden
	}
	tx, err := configchange.Begin(ctx, s.db, "group")
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	groups, err := readGroups(ctx, tx, id)
	if err != nil {
		return err
	}
	if id == "" || len(groups) != 1 || groups[0].Deleted {
		return sql.ErrNoRows
	}
	if groups[0].Revision != revision || revision >= (1<<53)-1 {
		return ErrConflict
	}
	// Retain a tombstone so existing rules and historical audits still refer
	// to the same immutable resource. Deleted groups have no memberships and
	// cannot be edited or resurrected, even when their old name is reused.
	if _, err := tx.ExecContext(ctx, `UPDATE traffic_groups SET deleted=1,revision=revision+1,updated_at=? WHERE id=?`, time.Now().Unix(), id); err != nil {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_group_members WHERE group_id=?`, id); err != nil {
		return err
	}
	ctx, err = groupAuditContext(ctx, &groups[0], nil)
	if err != nil {
		return err
	}
	if err := recordEvent(ctx, tx, "group.deleted", actor.UserID, id); err != nil {
		return err
	}
	after := groups[0]
	after.Deleted = true
	after.Members = []string{}
	after.Revision++
	after.UpdatedAt = time.Now().Unix()
	if err := configchange.RecordValues(ctx, s.db, tx, "group", id, after.Revision, groups[0], after, groups[0], after); err != nil {
		return err
	}
	return configchange.Commit(ctx, tx)
}
