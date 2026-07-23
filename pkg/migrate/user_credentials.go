package migrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractuser "github.com/Asutorufa/yuhaiin/pkg/contract/user"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
)

const legacyCredentialMigration = "legacy_credentials_to_users_v2"

// MigrateLegacyCredentials moves credentials which were stored inline in the
// plain inbound/node JSON into users_v2. The whole operation is one SQLite
// transaction. Source and dedup rows make retries safe even when the old
// fields remain in the compatibility structs.
func MigrateLegacyCredentials(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("user credential migration database is nil")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin user credential migration failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var status string
	err = tx.QueryRowContext(ctx, `
		SELECT status FROM user_migration_state_v2 WHERE migration_name = ?
	`, legacyCredentialMigration).Scan(&status)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("read user credential migration state failed: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_migration_state_v2(migration_name, status)
		VALUES (?, 'running')
		ON CONFLICT(migration_name) DO UPDATE SET status = 'running', completed_at = NULL
	`, legacyCredentialMigration); err != nil {
		return fmt.Errorf("mark user credential migration running failed: %w", err)
	}

	if err := migrateInbounds(ctx, tx); err != nil {
		return err
	}
	if err := migrateNodes(ctx, tx); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE user_migration_state_v2
		SET status = 'completed', completed_at = unixepoch()
		WHERE migration_name = ?
	`, legacyCredentialMigration); err != nil {
		return fmt.Errorf("mark user credential migration completed failed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user credential migration failed: %w", err)
	}
	return nil
}

func migrateInbounds(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, data_json FROM inbounds_v2 ORDER BY id`)
	if err != nil {
		return fmt.Errorf("query inbounds for user migration failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sourceID, data string
		if err := rows.Scan(&sourceID, &data); err != nil {
			return fmt.Errorf("scan inbound for user migration failed: %w", err)
		}
		var inbound contractinbound.Inbound
		if err := json.Unmarshal([]byte(data), &inbound); err != nil {
			return fmt.Errorf("decode inbound %q for user migration failed: %w", sourceID, err)
		}
		if err := migrateInboundProtocol(ctx, tx, sourceID, inbound.Protocol); err != nil {
			return err
		}
		for i, transport := range inbound.Transports {
			if transport.Type != contractinbound.TransportAEAD || transport.AEAD == nil || transport.AEAD.Password == "" {
				continue
			}
			credential := basicCredential(nil, &transport.AEAD.Password, false, false)
			if _, err := ensureMigratedUser(ctx, tx, "inbound", sourceID, fmt.Sprintf("transport[%d].aead", i), credential, "Inbound "+sourceID); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func migrateInboundProtocol(ctx context.Context, tx *sql.Tx, sourceID string, protocol contractinbound.Protocol) error {
	switch protocol.Type {
	case contractinbound.ProtocolHTTP:
		if protocol.HTTP == nil || (protocol.HTTP.Username == "" && protocol.HTTP.Password == "") {
			return nil
		}
		credential := basicCredential(&protocol.HTTP.Username, &protocol.HTTP.Password, protocol.HTTP.Username == "", protocol.HTTP.Password == "")
		_, err := ensureMigratedUser(ctx, tx, "inbound", sourceID, "protocol.http", credential, "Inbound "+sourceID)
		return err
	case contractinbound.ProtocolSocks5:
		if protocol.Socks5 == nil || (protocol.Socks5.Username == "" && protocol.Socks5.Password == "") {
			return nil
		}
		credential := basicCredential(&protocol.Socks5.Username, &protocol.Socks5.Password, protocol.Socks5.Username == "", protocol.Socks5.Password == "")
		_, err := ensureMigratedUser(ctx, tx, "inbound", sourceID, "protocol.socks5", credential, "Inbound "+sourceID)
		return err
	case contractinbound.ProtocolMixed:
		if protocol.Mixed == nil || (protocol.Mixed.Username == "" && protocol.Mixed.Password == "") {
			return nil
		}
		credential := basicCredential(&protocol.Mixed.Username, &protocol.Mixed.Password, protocol.Mixed.Username == "", protocol.Mixed.Password == "")
		_, err := ensureMigratedUser(ctx, tx, "inbound", sourceID, "protocol.mixed", credential, "Inbound "+sourceID)
		return err
	case contractinbound.ProtocolSocks4A:
		if protocol.Socks4A == nil || protocol.Socks4A.Username == "" {
			return nil
		}
		credential := basicCredential(&protocol.Socks4A.Username, nil, false, true)
		_, err := ensureMigratedUser(ctx, tx, "inbound", sourceID, "protocol.socks4a", credential, "Inbound "+sourceID)
		return err
	case contractinbound.ProtocolYuubinsya:
		if protocol.Yuubinsya == nil {
			return nil
		}
		credential := basicCredential(nil, &protocol.Yuubinsya.Password, true, false)
		_, err := ensureMigratedUser(ctx, tx, "inbound", sourceID, "protocol.yuubinsya", credential, "Inbound "+sourceID)
		return err
	default:
		return nil
	}
}

func migrateNodes(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, data_json FROM nodes_v2 ORDER BY id`)
	if err != nil {
		return fmt.Errorf("query nodes for user migration failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sourceID, data string
		if err := rows.Scan(&sourceID, &data); err != nil {
			return fmt.Errorf("scan node for user migration failed: %w", err)
		}
		var node contractnode.Node
		if err := json.Unmarshal([]byte(data), &node); err != nil {
			return fmt.Errorf("decode node %q for user migration failed: %w", sourceID, err)
		}
		changed, err := migrateNodeChain(ctx, tx, sourceID, node.Chain, "chain")
		if err != nil {
			return err
		}
		if !changed {
			continue
		}
		updated, err := json.Marshal(node)
		if err != nil {
			return fmt.Errorf("encode migrated node %q failed: %w", sourceID, err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE nodes_v2 SET data_json = ?, updated_at = unixepoch() WHERE id = ?
		`, string(updated), sourceID); err != nil {
			return fmt.Errorf("save migrated node %q failed: %w", sourceID, err)
		}
	}
	return rows.Err()
}

func migrateNodeChain(ctx context.Context, tx *sql.Tx, sourceID string, chain []contractnode.Protocol, prefix string) (bool, error) {
	changed := false
	for i := range chain {
		path := fmt.Sprintf("%s[%d]", prefix, i)
		protocol := &chain[i]
		var userID string
		var err error
		switch protocol.Type {
		case "shadowsocks":
			if protocol.Shadowsocks != nil && protocol.Shadowsocks.UserID == "" && protocol.Shadowsocks.Password != "" {
				userID, err = ensureMigratedUser(ctx, tx, "node", sourceID, path+".shadowsocks", basicCredential(nil, &protocol.Shadowsocks.Password, true, false), "Node "+sourceID)
				protocol.Shadowsocks.UserID = userID
			}
		case "shadowsocksr":
			if protocol.Shadowsocksr != nil && protocol.Shadowsocksr.UserID == "" && protocol.Shadowsocksr.Password != "" {
				userID, err = ensureMigratedUser(ctx, tx, "node", sourceID, path+".shadowsocksr", basicCredential(nil, &protocol.Shadowsocksr.Password, true, false), "Node "+sourceID)
				protocol.Shadowsocksr.UserID = userID
			}
		case "vmess":
			if protocol.Vmess != nil && protocol.Vmess.UserID == "" && protocol.Vmess.UUID != "" {
				userID, err = ensureMigratedUser(ctx, tx, "node", sourceID, path+".vmess", uuidCredential(protocol.Vmess.UUID), "Node "+sourceID)
				protocol.Vmess.UserID = userID
			}
		case "vless":
			if protocol.Vless != nil && protocol.Vless.UserID == "" && protocol.Vless.UUID != "" {
				userID, err = ensureMigratedUser(ctx, tx, "node", sourceID, path+".vless", uuidCredential(protocol.Vless.UUID), "Node "+sourceID)
				protocol.Vless.UserID = userID
			}
		case "trojan":
			if protocol.Trojan != nil && protocol.Trojan.UserID == "" && protocol.Trojan.Password != "" {
				userID, err = ensureMigratedUser(ctx, tx, "node", sourceID, path+".trojan", basicCredential(nil, &protocol.Trojan.Password, true, false), "Node "+sourceID)
				protocol.Trojan.UserID = userID
			}
		case "socks5":
			if protocol.Socks5 != nil && protocol.Socks5.UserID == "" && (protocol.Socks5.User != "" || protocol.Socks5.Password != "") {
				userID, err = ensureMigratedUser(ctx, tx, "node", sourceID, path+".socks5", basicCredential(&protocol.Socks5.User, &protocol.Socks5.Password, protocol.Socks5.User == "", protocol.Socks5.Password == ""), "Node "+sourceID)
				protocol.Socks5.UserID = userID
			}
		case "http":
			if protocol.HTTP != nil && protocol.HTTP.UserID == "" && (protocol.HTTP.User != "" || protocol.HTTP.Password != "") {
				userID, err = ensureMigratedUser(ctx, tx, "node", sourceID, path+".http", basicCredential(&protocol.HTTP.User, &protocol.HTTP.Password, protocol.HTTP.User == "", protocol.HTTP.Password == ""), "Node "+sourceID)
				protocol.HTTP.UserID = userID
			}
		case "yuubinsya":
			if protocol.Yuubinsya != nil && protocol.Yuubinsya.UserID == "" && protocol.Yuubinsya.Password != "" {
				userID, err = ensureMigratedUser(ctx, tx, "node", sourceID, path+".yuubinsya", basicCredential(nil, &protocol.Yuubinsya.Password, true, false), "Node "+sourceID)
				protocol.Yuubinsya.UserID = userID
			}
		case "tailscale":
			if protocol.Tailscale != nil && protocol.Tailscale.UserID == "" && protocol.Tailscale.AuthKey != "" {
				userID, err = ensureMigratedUser(ctx, tx, "node", sourceID, path+".tailscale", tokenCredential(protocol.Tailscale.AuthKey), "Node "+sourceID)
				protocol.Tailscale.UserID = userID
			}
		case "aead":
			if protocol.AEAD != nil && protocol.AEAD.UserID == "" && protocol.AEAD.Password != "" {
				userID, err = ensureMigratedUser(ctx, tx, "node", sourceID, path+".aead", basicCredential(nil, &protocol.AEAD.Password, true, false), "Node "+sourceID)
				protocol.AEAD.UserID = userID
			}
		case "network_split":
			if protocol.NetworkSplit != nil {
				if protocol.NetworkSplit.TCP != nil {
					var nested bool
					nested, err = migrateNodeChain(ctx, tx, sourceID, []contractnode.Protocol{*protocol.NetworkSplit.TCP}, path+".tcp")
					changed = changed || nested
					if err == nil {
						*protocol.NetworkSplit.TCP = []contractnode.Protocol{*protocol.NetworkSplit.TCP}[0]
					}
				}
				if err == nil && protocol.NetworkSplit.UDP != nil {
					var nested bool
					nested, err = migrateNodeChain(ctx, tx, sourceID, []contractnode.Protocol{*protocol.NetworkSplit.UDP}, path+".udp")
					changed = changed || nested
					if err == nil {
						*protocol.NetworkSplit.UDP = []contractnode.Protocol{*protocol.NetworkSplit.UDP}[0]
					}
				}
			}
		}
		if err != nil {
			return false, err
		}
		if userID != "" {
			changed = true
		}
	}
	return changed, nil
}

func basicCredential(username, password *string, allowAnyUsername, allowAnyPassword bool) contractuser.Credential {
	return contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{
		Username: username, Password: password, AllowAnyUsername: allowAnyUsername, AllowAnyPassword: allowAnyPassword,
	}}
}

func uuidCredential(value string) contractuser.Credential {
	return contractuser.Credential{Type: contractuser.CredentialUUID, UUID: &contractuser.UUIDCredential{UUID: value}}
}

func tokenCredential(value string) contractuser.Credential {
	return contractuser.Credential{Type: contractuser.CredentialToken, Token: &contractuser.TokenCredential{Token: value}}
}

func ensureMigratedUser(ctx context.Context, tx *sql.Tx, sourceKind, sourceID, sourcePath string, credential contractuser.Credential, name string) (string, error) {
	key := credentialKey(credential)
	var userID string
	err := tx.QueryRowContext(ctx, `
		SELECT user_id FROM user_migration_sources_v2
		WHERE migration_name = ? AND source_kind = ? AND source_id = ? AND source_path = ?
	`, legacyCredentialMigration, sourceKind, sourceID, sourcePath).Scan(&userID)
	if err == nil {
		return userID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("query migrated credential source %s/%s failed: %w", sourceKind, sourceID, err)
	}

	err = tx.QueryRowContext(ctx, `
		SELECT user_id FROM user_migration_dedup_v2
		WHERE migration_name = ? AND dedup_scope = 'local' AND dedup_key = ?
	`, legacyCredentialMigration, key[:]).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		userID, err = findEquivalentUser(ctx, tx, credential)
		if errors.Is(err, sql.ErrNoRows) {
			userID = id.GenerateUUID().String()
			usage := contractuser.UsageOutbound
			if sourceKind == "inbound" {
				usage = contractuser.UsageInbound
			}
			if err := insertMigratedUser(ctx, tx, userID, name, usage, credential); err != nil {
				return "", err
			}
		} else if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", fmt.Errorf("query migrated credential dedup failed: %w", err)
	}
	usage := contractuser.UsageOutbound
	if sourceKind == "inbound" {
		usage = contractuser.UsageInbound
	}
	if err := mergeUsage(ctx, tx, userID, usage); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_migration_dedup_v2(migration_name, dedup_scope, dedup_key, user_id)
		VALUES (?, 'local', ?, ?)
		ON CONFLICT(migration_name, dedup_scope, dedup_key) DO NOTHING
	`, legacyCredentialMigration, key[:], userID); err != nil {
		return "", fmt.Errorf("record migrated credential dedup failed: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_migration_sources_v2(migration_name, source_kind, source_id, source_path, dedup_scope, dedup_key, user_id, migrated_at)
		VALUES (?, ?, ?, ?, 'local', ?, ?, ?)
	`, legacyCredentialMigration, sourceKind, sourceID, sourcePath, key[:], userID, time.Now().Unix()); err != nil {
		return "", fmt.Errorf("record migrated credential source failed: %w", err)
	}
	return userID, nil
}

func insertMigratedUser(ctx context.Context, tx *sql.Tx, userID, name string, usage contractuser.Usage, credential contractuser.Credential) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users_v2(id, name, enabled, origin, usage, credential_type, updated_at)
		VALUES (?, ?, 1, 'migrated', ?, ?, ?)
	`, userID, name, usage, credential.Type, time.Now().Unix()); err != nil {
		return fmt.Errorf("insert migrated user failed: %w", err)
	}
	switch credential.Type {
	case contractuser.CredentialBasic:
		c := credential.Basic
		var username, password any
		if c.Username != nil {
			username = *c.Username
		}
		if c.Password != nil {
			password = *c.Password
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO user_basic_v2(user_id, username, password, allow_any_username, allow_any_password) VALUES (?, ?, ?, ?, ?)`, userID, username, password, boolInt(c.AllowAnyUsername), boolInt(c.AllowAnyPassword))
		return err
	case contractuser.CredentialUUID:
		_, err := tx.ExecContext(ctx, `INSERT INTO user_uuid_v2(user_id, uuid) VALUES (?, ?)`, userID, credential.UUID.UUID)
		return err
	case contractuser.CredentialToken:
		_, err := tx.ExecContext(ctx, `INSERT INTO user_token_v2(user_id, token) VALUES (?, ?)`, userID, credential.Token.Token)
		return err
	default:
		return fmt.Errorf("unsupported migrated credential type %q", credential.Type)
	}
}

func findEquivalentUser(ctx context.Context, tx *sql.Tx, credential contractuser.Credential) (string, error) {
	switch credential.Type {
	case contractuser.CredentialBasic:
		c := credential.Basic
		var username, password any
		if c.Username != nil {
			username = *c.Username
		}
		if c.Password != nil {
			password = *c.Password
		}
		var userID string
		err := tx.QueryRowContext(ctx, `
			SELECT u.id FROM users_v2 u JOIN user_basic_v2 b ON b.user_id = u.id
			WHERE u.credential_type = 'basic' AND b.username IS ? AND b.password IS ?
			AND b.allow_any_username = ? AND b.allow_any_password = ? LIMIT 1
		`, username, password, boolInt(c.AllowAnyUsername), boolInt(c.AllowAnyPassword)).Scan(&userID)
		return userID, err
	case contractuser.CredentialUUID:
		var userID string
		err := tx.QueryRowContext(ctx, `SELECT user_id FROM user_uuid_v2 WHERE uuid = ?`, credential.UUID.UUID).Scan(&userID)
		return userID, err
	case contractuser.CredentialToken:
		var userID string
		err := tx.QueryRowContext(ctx, `SELECT user_id FROM user_token_v2 WHERE token = ?`, credential.Token.Token).Scan(&userID)
		return userID, err
	default:
		return "", sql.ErrNoRows
	}
}

func mergeUsage(ctx context.Context, tx *sql.Tx, userID string, usage contractuser.Usage) error {
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT usage FROM users_v2 WHERE id = ?`, userID).Scan(&current); err != nil {
		return fmt.Errorf("read migrated user usage failed: %w", err)
	}
	if current == string(usage) || current == string(contractuser.UsageBoth) {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users_v2 SET usage = 'both' WHERE id = ?`, userID); err != nil {
		return fmt.Errorf("merge migrated user usage failed: %w", err)
	}
	return nil
}

func credentialKey(credential contractuser.Credential) [32]byte {
	var value string
	switch credential.Type {
	case contractuser.CredentialBasic:
		c := credential.Basic
		value = fmt.Sprintf("basic|%q|%q|%t|%t", optional(c.Username), optional(c.Password), c.AllowAnyUsername, c.AllowAnyPassword)
	case contractuser.CredentialUUID:
		value = fmt.Sprintf("uuid|%q", credential.UUID.UUID)
	case contractuser.CredentialToken:
		value = fmt.Sprintf("token|%q", credential.Token.Token)
	}
	return sha256.Sum256([]byte(value))
}

func optional(value *string) string {
	if value == nil {
		return "<nil>"
	}
	return *value
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
