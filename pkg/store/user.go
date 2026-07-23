package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractuser "github.com/Asutorufa/yuhaiin/pkg/contract/user"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
)

type UserStore struct {
	db *sql.DB
}

var ErrUserReferenced = errors.New("user is referenced by a node or migration mapping")

func NewUserStore(db *sql.DB) *UserStore { return &UserStore{db: db} }

func (s *UserStore) List(ctx context.Context) ([]contractuser.UserView, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("user store database is nil")
	}
	references, err := s.outboundReferences(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.name, u.enabled, u.origin, u.usage, u.credential_type,
		       b.username, b.password, b.allow_any_username, b.allow_any_password,
		       uuid.uuid, token.token
		FROM users_v2 u
		LEFT JOIN user_basic_v2 b ON b.user_id = u.id AND u.credential_type = 'basic'
		LEFT JOIN user_uuid_v2 uuid ON uuid.user_id = u.id AND u.credential_type = 'uuid'
		LEFT JOIN user_token_v2 token ON token.user_id = u.id AND u.credential_type = 'token'
		ORDER BY u.name, u.id
	`)
	if err != nil {
		return nil, fmt.Errorf("query users failed: %w", err)
	}
	defer rows.Close()

	var result []contractuser.UserView
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		view := user.View()
		view.OutboundReferences = references[user.ID]
		result = append(result, view)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users failed: %w", err)
	}
	return result, nil
}

// ListUsers is intentionally internal-facing: AuthCenter is the only caller
// that should receive credential material from the store.
func (s *UserStore) ListUsers(ctx context.Context) ([]contractuser.User, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("user store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.name, u.enabled, u.origin, u.usage, u.credential_type,
		       b.username, b.password, b.allow_any_username, b.allow_any_password,
		       uuid.uuid, token.token
		FROM users_v2 u
		LEFT JOIN user_basic_v2 b ON b.user_id = u.id AND u.credential_type = 'basic'
		LEFT JOIN user_uuid_v2 uuid ON uuid.user_id = u.id AND u.credential_type = 'uuid'
		LEFT JOIN user_token_v2 token ON token.user_id = u.id AND u.credential_type = 'token'
		ORDER BY u.name, u.id
	`)
	if err != nil {
		return nil, fmt.Errorf("query users with credentials failed: %w", err)
	}
	defer rows.Close()
	var result []contractuser.User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users with credentials failed: %w", err)
	}
	return result, nil
}

func (s *UserStore) Get(ctx context.Context, userID string) (contractuser.User, error) {
	if s == nil || s.db == nil {
		return contractuser.User{}, errors.New("user store database is nil")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.name, u.enabled, u.origin, u.usage, u.credential_type,
		       b.username, b.password, b.allow_any_username, b.allow_any_password,
		       uuid.uuid, token.token
		FROM users_v2 u
		LEFT JOIN user_basic_v2 b ON b.user_id = u.id AND u.credential_type = 'basic'
		LEFT JOIN user_uuid_v2 uuid ON uuid.user_id = u.id AND u.credential_type = 'uuid'
		LEFT JOIN user_token_v2 token ON token.user_id = u.id AND u.credential_type = 'token'
		WHERE u.id = ?
	`, userID)
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return contractuser.User{}, fmt.Errorf("%w: user %s", ErrNotFound, userID)
	}
	if err != nil {
		return contractuser.User{}, fmt.Errorf("query user %q failed: %w", userID, err)
	}
	return user, nil
}

func (s *UserStore) Create(ctx context.Context, write contractuser.UserWrite) (contractuser.UserView, error) {
	write.Origin = defaultOrigin(write.Origin)
	if err := write.Validate(); err != nil {
		return contractuser.UserView{}, err
	}
	user := contractuser.User{
		ID:         id.GenerateUUID().String(),
		Name:       write.Name,
		Enabled:    write.Enabled,
		Origin:     write.Origin,
		Usage:      write.Usage,
		Credential: write.Credential,
	}
	if err := s.Save(ctx, user, 0); err != nil {
		return contractuser.UserView{}, err
	}
	return user.View(), nil
}

func (s *UserStore) Save(ctx context.Context, user contractuser.User, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("user store database is nil")
	}
	if user.Origin == "" {
		user.Origin = contractuser.OriginManual
	}
	if err := user.Validate(); err != nil {
		return err
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin user save transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users_v2(id, name, enabled, origin, usage, credential_type, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			enabled = excluded.enabled,
			origin = excluded.origin,
			usage = excluded.usage,
			credential_type = excluded.credential_type,
			updated_at = excluded.updated_at
	`, user.ID, user.Name, boolToInt(user.Enabled), user.Origin, user.Usage, user.Credential.Type, updatedAt); err != nil {
		return fmt.Errorf("upsert user %q failed: %w", user.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_basic_v2 WHERE user_id = ?`, user.ID); err != nil {
		return fmt.Errorf("clear basic credential %q failed: %w", user.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_uuid_v2 WHERE user_id = ?`, user.ID); err != nil {
		return fmt.Errorf("clear uuid credential %q failed: %w", user.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_token_v2 WHERE user_id = ?`, user.ID); err != nil {
		return fmt.Errorf("clear token credential %q failed: %w", user.ID, err)
	}
	switch user.Credential.Type {
	case contractuser.CredentialBasic:
		c := user.Credential.Basic
		var username, password any
		if c.Username != nil {
			username = *c.Username
		}
		if c.Password != nil {
			password = *c.Password
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO user_basic_v2(user_id, username, password, allow_any_username, allow_any_password)
			VALUES (?, ?, ?, ?, ?)
		`, user.ID, username, password, boolToInt(c.AllowAnyUsername), boolToInt(c.AllowAnyPassword)); err != nil {
			return fmt.Errorf("insert basic credential %q failed: %w", user.ID, err)
		}
	case contractuser.CredentialUUID:
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_uuid_v2(user_id, uuid) VALUES (?, ?)`, user.ID, user.Credential.UUID.UUID); err != nil {
			return fmt.Errorf("insert uuid credential %q failed: %w", user.ID, err)
		}
	case contractuser.CredentialToken:
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_token_v2(user_id, token) VALUES (?, ?)`, user.ID, user.Credential.Token.Token); err != nil {
			return fmt.Errorf("insert token credential %q failed: %w", user.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user save transaction failed: %w", err)
	}
	return nil
}

func (s *UserStore) Delete(ctx context.Context, userID string) error {
	if s == nil || s.db == nil {
		return errors.New("user store database is nil")
	}
	references, err := s.outboundReferences(ctx)
	if err != nil {
		return err
	}
	if references[userID] > 0 {
		return fmt.Errorf("%w: user %s", ErrUserReferenced, userID)
	}
	var migrationReferences int
	if err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM user_migration_sources_v2 WHERE user_id = ?) +
			(SELECT COUNT(*) FROM user_migration_dedup_v2 WHERE user_id = ?)
	`, userID, userID).Scan(&migrationReferences); err != nil {
		return fmt.Errorf("check user migration references failed: %w", err)
	}
	if migrationReferences > 0 {
		return fmt.Errorf("%w: user %s", ErrUserReferenced, userID)
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM users_v2 WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("delete user %q failed: %w", userID, err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("%w: user %s", ErrNotFound, userID)
	}
	return nil
}

func (s *UserStore) outboundReferences(ctx context.Context) (map[string]int, error) {
	references := make(map[string]int)
	rows, err := s.db.QueryContext(ctx, `SELECT data_json FROM nodes_v2`)
	if err != nil {
		return nil, fmt.Errorf("query node user references failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scan node user references failed: %w", err)
		}
		var node contractnode.Node
		if err := json.Unmarshal([]byte(data), &node); err != nil {
			return nil, fmt.Errorf("decode node user references failed: %w", err)
		}
		countProtocolReferences(references, node.Chain)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node user references failed: %w", err)
	}
	return references, nil
}

func countProtocolReferences(references map[string]int, protocols []contractnode.Protocol) {
	for _, protocol := range protocols {
		var userID string
		switch protocol.Type {
		case "shadowsocks":
			if protocol.Shadowsocks != nil {
				userID = protocol.Shadowsocks.UserID
			}
		case "shadowsocksr":
			if protocol.Shadowsocksr != nil {
				userID = protocol.Shadowsocksr.UserID
			}
		case "vmess":
			if protocol.Vmess != nil {
				userID = protocol.Vmess.UserID
			}
		case "vless":
			if protocol.Vless != nil {
				userID = protocol.Vless.UserID
			}
		case "trojan":
			if protocol.Trojan != nil {
				userID = protocol.Trojan.UserID
			}
		case "socks5":
			if protocol.Socks5 != nil {
				userID = protocol.Socks5.UserID
			}
		case "http":
			if protocol.HTTP != nil {
				userID = protocol.HTTP.UserID
			}
		case "yuubinsya":
			if protocol.Yuubinsya != nil {
				userID = protocol.Yuubinsya.UserID
			}
		case "tailscale":
			if protocol.Tailscale != nil {
				userID = protocol.Tailscale.UserID
			}
		case "aead":
			if protocol.AEAD != nil {
				userID = protocol.AEAD.UserID
			}
		case "network_split":
			if protocol.NetworkSplit != nil {
				if protocol.NetworkSplit.TCP != nil {
					countProtocolReferences(references, []contractnode.Protocol{*protocol.NetworkSplit.TCP})
				}
				if protocol.NetworkSplit.UDP != nil {
					countProtocolReferences(references, []contractnode.Protocol{*protocol.NetworkSplit.UDP})
				}
			}
		}
		if userID != "" {
			references[userID]++
		}
	}
}

type sqlScanner interface{ Scan(...any) error }

func scanUser(scanner sqlScanner) (contractuser.User, error) {
	var user contractuser.User
	var enabled int
	var credentialType, origin, usage string
	var username, password, uuidValue, token sql.NullString
	var anyUsername, anyPassword sql.NullInt64
	if err := scanner.Scan(&user.ID, &user.Name, &enabled, &origin, &usage, &credentialType, &username, &password, &anyUsername, &anyPassword, &uuidValue, &token); err != nil {
		return contractuser.User{}, err
	}
	user.Enabled = enabled != 0
	user.Origin = contractuser.Origin(origin)
	user.Usage = contractuser.Usage(usage)
	user.Credential.Type = contractuser.CredentialType(credentialType)
	switch user.Credential.Type {
	case contractuser.CredentialBasic:
		basic := &contractuser.BasicCredential{AllowAnyUsername: anyUsername.Valid && anyUsername.Int64 != 0, AllowAnyPassword: anyPassword.Valid && anyPassword.Int64 != 0}
		if username.Valid {
			basic.Username = &username.String
		}
		if password.Valid {
			basic.Password = &password.String
		}
		user.Credential.Basic = basic
	case contractuser.CredentialUUID:
		user.Credential.UUID = &contractuser.UUIDCredential{UUID: uuidValue.String}
	case contractuser.CredentialToken:
		user.Credential.Token = &contractuser.TokenCredential{Token: token.String}
	}
	return user, nil
}

func defaultOrigin(value contractuser.Origin) contractuser.Origin {
	if value == "" {
		return contractuser.OriginManual
	}
	return value
}
