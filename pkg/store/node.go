package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractuser "github.com/Asutorufa/yuhaiin/pkg/contract/user"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
)

type NodeStore struct {
	db *sql.DB
}

const (
	selectedTCPNodeMetadataKey = "selected_tcp_node_v2"
	selectedUDPNodeMetadataKey = "selected_udp_node_v2"
)

func NewNodeStore(db *sql.DB) *NodeStore {
	return &NodeStore{db: db}
}

type NodeExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type NodeQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *NodeStore) Save(ctx context.Context, node contractnode.Node, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node save transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM subscription_nodes_v2 WHERE node_id = ?`, node.ID); err != nil {
		return fmt.Errorf("detach node %q from subscriptions failed: %w", node.ID, err)
	}
	if err := SaveNodeContract(ctx, tx, node, updatedAt); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit node save transaction failed: %w", err)
	}
	return nil
}

func (s *NodeStore) ReplaceRemote(ctx context.Context, subscriptionName string, nodes []contractnode.Node, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin remote node replace transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	oldIDs, err := subscriptionNodeIDs(ctx, tx, subscriptionName)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM subscription_nodes_v2 WHERE subscription_name = ?`, subscriptionName); err != nil {
		return fmt.Errorf("clear subscription nodes for %q failed: %w", subscriptionName, err)
	}
	// Keep the user links across refreshes. If a subscription changes a
	// credential, the old migrated user remains attributable to that
	// subscription and can be cleaned up when the subscription is deleted.
	for _, nodeID := range oldIDs {
		var references int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM subscription_nodes_v2 WHERE node_id = ?`, nodeID).Scan(&references); err != nil {
			return fmt.Errorf("check subscription node %q references failed: %w", nodeID, err)
		}
		if references != 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM node_tags_v2 WHERE EXISTS (SELECT 1 FROM json_each(node_tags_v2.members_json) WHERE value = ?)`, nodeID); err != nil {
			return fmt.Errorf("delete tags for remote node %q failed: %w", nodeID, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM nodes_v2 WHERE id = ?`, nodeID); err != nil {
			return fmt.Errorf("delete replaced remote node %q failed: %w", nodeID, err)
		}
	}
	for _, node := range nodes {
		node.Group = subscriptionName
		node.Origin = "remote"
		if node.ID == "" {
			node.ID = id.GenerateUUID().String()
		}
		if err := migrateSubscriptionNodeCredentials(ctx, tx, subscriptionName, node.ID, node.Chain); err != nil {
			return err
		}
		if err := SaveNodeContract(ctx, tx, node, updatedAt); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO subscription_nodes_v2(subscription_name, node_id) VALUES (?, ?)`, subscriptionName, node.ID); err != nil {
			return fmt.Errorf("link node %q to subscription %q failed: %w", node.ID, subscriptionName, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit remote node replace transaction failed: %w", err)
	}
	return nil
}

func subscriptionNodeIDs(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, subscriptionName string) ([]string, error) {
	rows, err := queryer.QueryContext(ctx, `SELECT node_id FROM subscription_nodes_v2 WHERE subscription_name = ?`, subscriptionName)
	if err != nil {
		return nil, fmt.Errorf("query subscription nodes for %q failed: %w", subscriptionName, err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan subscription node for %q failed: %w", subscriptionName, err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscription nodes for %q failed: %w", subscriptionName, err)
	}
	return ids, nil
}

type subscriptionCredentialBinding struct {
	credential contractuser.Credential
	setUserID  func(string)
	clear      func()
	available  bool
}

func migrateSubscriptionNodeCredentials(ctx context.Context, tx *sql.Tx, subscriptionName, nodeID string, chain []contractnode.Protocol) error {
	for index := range chain {
		protocol := &chain[index]
		if protocol.Type == "network_split" && protocol.NetworkSplit != nil {
			if protocol.NetworkSplit.TCP != nil {
				nested := []contractnode.Protocol{*protocol.NetworkSplit.TCP}
				if err := migrateSubscriptionNodeCredentials(ctx, tx, subscriptionName, nodeID, nested); err != nil {
					return err
				}
				*protocol.NetworkSplit.TCP = nested[0]
			}
			if protocol.NetworkSplit.UDP != nil {
				nested := []contractnode.Protocol{*protocol.NetworkSplit.UDP}
				if err := migrateSubscriptionNodeCredentials(ctx, tx, subscriptionName, nodeID, nested); err != nil {
					return err
				}
				*protocol.NetworkSplit.UDP = nested[0]
			}
			continue
		}
		binding := subscriptionCredentialBindingFor(protocol)
		if binding.clear == nil {
			continue
		}
		binding.clear()
		if !binding.available {
			continue
		}
		userID, err := ensureSubscriptionUser(ctx, tx, subscriptionName, binding.credential)
		if err != nil {
			return fmt.Errorf("migrate subscription node %q chain[%d] credentials: %w", nodeID, index, err)
		}
		binding.setUserID(userID)
	}
	return nil
}

func subscriptionCredentialBindingFor(protocol *contractnode.Protocol) subscriptionCredentialBinding {
	if protocol == nil {
		return subscriptionCredentialBinding{}
	}
	allowAny := func(username, password string) contractuser.Credential {
		var usernameValue, passwordValue *string
		if username != "" {
			usernameValue = &username
		}
		if password != "" || username != "" {
			passwordValue = &password
		}
		return contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{
			Username: usernameValue, Password: passwordValue, AllowAnyUsername: username == "", AllowAnyPassword: password == "",
		}}
	}
	switch protocol.Type {
	case "shadowsocks":
		if protocol.Shadowsocks == nil {
			return subscriptionCredentialBinding{}
		}
		value := protocol.Shadowsocks.Password //nolint:staticcheck // migrate legacy inline credentials.
		return subscriptionCredentialBinding{
			credential: allowAny("", value), available: value != "",
			setUserID: func(userID string) { protocol.Shadowsocks.UserID = userID },
			clear:     func() { protocol.Shadowsocks.UserID, protocol.Shadowsocks.Password = "", "" }, //nolint:staticcheck // clear the legacy inline credential after migration.
		}
	case "shadowsocksr":
		if protocol.Shadowsocksr == nil {
			return subscriptionCredentialBinding{}
		}
		value := protocol.Shadowsocksr.Password //nolint:staticcheck // migrate legacy inline credentials.
		return subscriptionCredentialBinding{
			credential: allowAny("", value), available: value != "",
			setUserID: func(userID string) { protocol.Shadowsocksr.UserID = userID },
			clear:     func() { protocol.Shadowsocksr.UserID, protocol.Shadowsocksr.Password = "", "" }, //nolint:staticcheck // clear the legacy inline credential after migration.
		}
	case "vmess":
		if protocol.Vmess == nil {
			return subscriptionCredentialBinding{}
		}
		value := protocol.Vmess.UUID //nolint:staticcheck // migrate legacy inline credentials.
		return subscriptionCredentialBinding{
			credential: contractuser.Credential{Type: contractuser.CredentialUUID, UUID: &contractuser.UUIDCredential{UUID: value}}, available: value != "",
			setUserID: func(userID string) { protocol.Vmess.UserID = userID },
			clear:     func() { protocol.Vmess.UserID, protocol.Vmess.UUID = "", "" }, //nolint:staticcheck // clear the legacy inline credential after migration.
		}
	case "vless":
		if protocol.Vless == nil {
			return subscriptionCredentialBinding{}
		}
		value := protocol.Vless.UUID //nolint:staticcheck // migrate legacy inline credentials.
		return subscriptionCredentialBinding{
			credential: contractuser.Credential{Type: contractuser.CredentialUUID, UUID: &contractuser.UUIDCredential{UUID: value}}, available: value != "",
			setUserID: func(userID string) { protocol.Vless.UserID = userID },
			clear:     func() { protocol.Vless.UserID, protocol.Vless.UUID = "", "" }, //nolint:staticcheck // clear the legacy inline credential after migration.
		}
	case "trojan":
		if protocol.Trojan == nil {
			return subscriptionCredentialBinding{}
		}
		value := protocol.Trojan.Password //nolint:staticcheck // migrate legacy inline credentials.
		return subscriptionCredentialBinding{
			credential: allowAny("", value), available: value != "",
			setUserID: func(userID string) { protocol.Trojan.UserID = userID },
			clear:     func() { protocol.Trojan.UserID, protocol.Trojan.Password = "", "" }, //nolint:staticcheck // clear the legacy inline credential after migration.
		}
	case "socks5":
		if protocol.Socks5 == nil {
			return subscriptionCredentialBinding{}
		}
		username, password := protocol.Socks5.User, protocol.Socks5.Password //nolint:staticcheck // migrate legacy inline credentials.
		return subscriptionCredentialBinding{
			credential: allowAny(username, password), available: username != "" || password != "",
			setUserID: func(userID string) { protocol.Socks5.UserID = userID },
			clear:     func() { protocol.Socks5.UserID, protocol.Socks5.User, protocol.Socks5.Password = "", "", "" }, //nolint:staticcheck // clear the legacy inline credential after migration.
		}
	case "http":
		if protocol.HTTP == nil {
			return subscriptionCredentialBinding{}
		}
		username, password := protocol.HTTP.User, protocol.HTTP.Password //nolint:staticcheck // migrate legacy inline credentials.
		return subscriptionCredentialBinding{
			credential: allowAny(username, password), available: username != "" || password != "",
			setUserID: func(userID string) { protocol.HTTP.UserID = userID },
			clear:     func() { protocol.HTTP.UserID, protocol.HTTP.User, protocol.HTTP.Password = "", "", "" }, //nolint:staticcheck // clear the legacy inline credential after migration.
		}
	case "yuubinsya":
		if protocol.Yuubinsya == nil {
			return subscriptionCredentialBinding{}
		}
		value := protocol.Yuubinsya.Password //nolint:staticcheck // migrate legacy inline credentials.
		return subscriptionCredentialBinding{
			credential: allowAny("", value), available: value != "",
			setUserID: func(userID string) { protocol.Yuubinsya.UserID = userID },
			clear:     func() { protocol.Yuubinsya.UserID, protocol.Yuubinsya.Password = "", "" }, //nolint:staticcheck // clear the legacy inline credential after migration.
		}
	case "tailscale":
		if protocol.Tailscale == nil {
			return subscriptionCredentialBinding{}
		}
		value := protocol.Tailscale.AuthKey //nolint:staticcheck // migrate legacy inline credentials.
		return subscriptionCredentialBinding{
			credential: contractuser.Credential{Type: contractuser.CredentialToken, Token: &contractuser.TokenCredential{Token: value}}, available: value != "",
			setUserID: func(userID string) { protocol.Tailscale.UserID = userID },
			clear:     func() { protocol.Tailscale.UserID, protocol.Tailscale.AuthKey = "", "" }, //nolint:staticcheck // clear the legacy inline credential after migration.
		}
	case "aead":
		if protocol.AEAD == nil {
			return subscriptionCredentialBinding{}
		}
		value := protocol.AEAD.Password //nolint:staticcheck // migrate legacy inline credentials.
		return subscriptionCredentialBinding{
			credential: allowAny("", value), available: value != "",
			setUserID: func(userID string) { protocol.AEAD.UserID = userID },
			clear:     func() { protocol.AEAD.UserID, protocol.AEAD.Password = "", "" }, //nolint:staticcheck // clear the legacy inline credential after migration.
		}
	default:
		return subscriptionCredentialBinding{}
	}
}

func ensureSubscriptionUser(ctx context.Context, tx *sql.Tx, subscriptionName string, credential contractuser.Credential) (string, error) {
	if err := credential.Validate(); err != nil {
		return "", err
	}
	var userID string
	var err error
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
		err = tx.QueryRowContext(ctx, `
			SELECT u.id FROM users_v2 u JOIN user_basic_v2 b ON b.user_id = u.id
			WHERE u.credential_type = 'basic' AND b.username IS ? AND b.password IS ?
			AND b.allow_any_username = ? AND b.allow_any_password = ? LIMIT 1
		`, username, password, boolToInt(c.AllowAnyUsername), boolToInt(c.AllowAnyPassword)).Scan(&userID)
	case contractuser.CredentialUUID:
		err = tx.QueryRowContext(ctx, `SELECT user_id FROM user_uuid_v2 WHERE uuid = ?`, credential.UUID.UUID).Scan(&userID)
	case contractuser.CredentialToken:
		err = tx.QueryRowContext(ctx, `SELECT user_id FROM user_token_v2 WHERE token = ?`, credential.Token.Token).Scan(&userID)
	}
	if errors.Is(err, sql.ErrNoRows) {
		userID = id.GenerateUUID().String()
		if err := insertSubscriptionUser(ctx, tx, userID, subscriptionName, credential); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", fmt.Errorf("find equivalent subscription user failed: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users_v2 SET usage = 'both' WHERE id = ? AND usage = 'inbound'`, userID); err != nil {
		return "", fmt.Errorf("enable outbound usage for subscription user %q failed: %w", userID, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO subscription_users_v2(subscription_name, user_id) VALUES (?, ?)
		ON CONFLICT(subscription_name, user_id) DO NOTHING
	`, subscriptionName, userID); err != nil {
		return "", fmt.Errorf("link user %q to subscription %q failed: %w", userID, subscriptionName, err)
	}
	return userID, nil
}

func insertSubscriptionUser(ctx context.Context, tx *sql.Tx, userID, subscriptionName string, credential contractuser.Credential) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users_v2(id, name, enabled, origin, usage, credential_type, updated_at)
		VALUES (?, ?, 1, 'migrated', 'outbound', ?, unixepoch())
	`, userID, "Subscription "+subscriptionName, credential.Type); err != nil {
		return fmt.Errorf("insert subscription user failed: %w", err)
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
		_, err := tx.ExecContext(ctx, `INSERT INTO user_basic_v2(user_id, username, password, allow_any_username, allow_any_password) VALUES (?, ?, ?, ?, ?)`, userID, username, password, boolToInt(c.AllowAnyUsername), boolToInt(c.AllowAnyPassword))
		return err
	case contractuser.CredentialUUID:
		_, err := tx.ExecContext(ctx, `INSERT INTO user_uuid_v2(user_id, uuid) VALUES (?, ?)`, userID, credential.UUID.UUID)
		return err
	case contractuser.CredentialToken:
		_, err := tx.ExecContext(ctx, `INSERT INTO user_token_v2(user_id, token) VALUES (?, ?)`, userID, credential.Token.Token)
		return err
	default:
		return fmt.Errorf("unsupported subscription credential type %q", credential.Type)
	}
}

func SaveNodeContract(ctx context.Context, execer NodeExecer, node contractnode.Node, updatedAt int64) error {
	if err := node.Validate(); err != nil {
		return err
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	dataJSON, err := json.Marshal(node)
	if err != nil {
		return fmt.Errorf("encode node contract %q failed: %w", node.ID, err)
	}
	chainTypes, err := json.Marshal(chainTypes(node.Chain))
	if err != nil {
		return fmt.Errorf("encode node chain types %q failed: %w", node.ID, err)
	}
	if _, err := execer.ExecContext(ctx, `
		INSERT INTO nodes_v2(id, name, group_name, origin, enabled, chain_types_json, updated_at, data_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			group_name = excluded.group_name,
			origin = excluded.origin,
			enabled = excluded.enabled,
			chain_types_json = excluded.chain_types_json,
			updated_at = excluded.updated_at,
			data_json = excluded.data_json
	`, node.ID, node.Name, node.Group, node.Origin, boolToInt(node.Enabled), string(chainTypes), updatedAt, string(dataJSON)); err != nil {
		return fmt.Errorf("upsert node contract %q failed: %w", node.ID, err)
	}
	return nil
}

func (s *NodeStore) Get(ctx context.Context, id string) (contractnode.Node, error) {
	if s == nil || s.db == nil {
		return contractnode.Node{}, errors.New("node store database is nil")
	}
	return getNodeContract(ctx, s.db, id)
}

func (s *NodeStore) List(ctx context.Context) ([]contractnode.Node, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("node store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT data_json
		FROM nodes_v2
		ORDER BY group_name, name, id
	`)
	if err != nil {
		return nil, fmt.Errorf("query node contracts failed: %w", err)
	}
	defer rows.Close()

	var nodes []contractnode.Node
	for rows.Next() {
		var dataJSON string
		if err := rows.Scan(&dataJSON); err != nil {
			return nil, fmt.Errorf("scan node contract failed: %w", err)
		}
		node, err := decodeNodeContract(dataJSON)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node contracts failed: %w", err)
	}
	return nodes, nil
}

func (s *NodeStore) Delete(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node delete transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM node_tags WHERE target_kind = 'node' AND target_id = ?`, id); err != nil {
		return fmt.Errorf("delete node tag members for %q failed: %w", id, err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM nodes_v2 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete node contract %q failed: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: node %s not found", ErrNotFound, id)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit node delete transaction failed: %w", err)
	}
	return nil
}

func (s *NodeStore) Selected(ctx context.Context, tcp bool) (contractnode.Node, bool, error) {
	if s == nil || s.db == nil {
		return contractnode.Node{}, false, errors.New("node store database is nil")
	}
	key := selectedUDPNodeMetadataKey
	if tcp {
		key = selectedTCPNodeMetadataKey
	}
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) || id == "" {
		return contractnode.Node{}, false, nil
	}
	if err != nil {
		return contractnode.Node{}, false, fmt.Errorf("load metadata %q failed: %w", key, err)
	}
	node, err := s.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return contractnode.Node{}, false, nil
	}
	return node, err == nil, err
}

func (s *NodeStore) Use(ctx context.Context, id string) error {
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	for key, value := range map[string]string{
		selectedTCPNodeMetadataKey: id,
		selectedUDPNodeMetadataKey: id,
	} {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO metadata(key, value)
			VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, key, value); err != nil {
			return fmt.Errorf("update metadata %q failed: %w", key, err)
		}
	}
	return nil
}

func (s *NodeStore) AddTag(ctx context.Context, tag, kind, target string) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	if kind == "" {
		kind = "node"
	}
	if kind != "node" && kind != "tag" {
		return fmt.Errorf("unknown node tag target kind %q", kind)
	}
	if tag == target && kind == "tag" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO node_tags(tag_name, target_kind, target_id, updated_at)
		VALUES (?, ?, ?, unixepoch())
		ON CONFLICT(tag_name, target_kind, target_id) DO UPDATE SET updated_at = excluded.updated_at
	`, tag, kind, target); err != nil {
		return fmt.Errorf("insert node tag failed: %w", err)
	}
	return nil
}

func (s *NodeStore) DeleteTag(ctx context.Context, tag string) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM node_tags WHERE tag_name = ?`, tag); err != nil {
		return fmt.Errorf("delete node tag %q failed: %w", tag, err)
	}
	return nil
}

type NodeTag struct {
	Name      string
	Kind      string
	TargetIDs []string
}

func (s *NodeStore) GetTag(ctx context.Context, name string) (NodeTag, bool, error) {
	if s == nil || s.db == nil {
		return NodeTag{}, false, errors.New("node store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT target_kind, target_id
		FROM node_tags
		WHERE tag_name = ?
		ORDER BY target_kind, target_id
	`, name)
	if err != nil {
		return NodeTag{}, false, fmt.Errorf("query node tag %q failed: %w", name, err)
	}
	defer rows.Close()
	tag := NodeTag{Name: name, Kind: "node"}
	for rows.Next() {
		var kind, targetID string
		if err := rows.Scan(&kind, &targetID); err != nil {
			return NodeTag{}, false, fmt.Errorf("scan node tag %q failed: %w", name, err)
		}
		if kind == "tag" {
			tag.Kind = "mirror"
		}
		tag.TargetIDs = append(tag.TargetIDs, targetID)
	}
	if err := rows.Err(); err != nil {
		return NodeTag{}, false, fmt.Errorf("iterate node tag %q failed: %w", name, err)
	}
	return tag, len(tag.TargetIDs) > 0, nil
}

func (s *NodeStore) UsingIDs(ctx context.Context) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("node store database is nil")
	}
	ids := map[string]struct{}{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT value
		FROM metadata
		WHERE key IN ('selected_tcp_node_v2', 'selected_udp_node_v2')
		UNION
		SELECT target_id
		FROM node_tags
		WHERE target_kind = 'node'
	`)
	if err != nil {
		return nil, fmt.Errorf("query using node ids failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan using node id failed: %w", err)
		}
		if id != "" {
			ids[id] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate using node ids failed: %w", err)
	}
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	slices.Sort(out)
	return out, nil
}

func DeleteNodeContract(ctx context.Context, execer NodeExecer, id string) error {
	if _, err := execer.ExecContext(ctx, `DELETE FROM nodes_v2 WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete node contract %q failed: %w", id, err)
	}
	return nil
}

func DeleteRemoteNodeContracts(ctx context.Context, execer NodeExecer, group string) error {
	if _, err := execer.ExecContext(ctx, `
		DELETE FROM nodes_v2
		WHERE id IN (SELECT node_id FROM subscription_nodes_v2 WHERE subscription_name = ?)
	`, group); err != nil {
		return fmt.Errorf("delete subscription node contracts for %q failed: %w", group, err)
	}
	return nil
}

func getNodeContract(ctx context.Context, queryer NodeQueryer, id string) (contractnode.Node, error) {
	var dataJSON string
	err := queryer.QueryRowContext(ctx, `SELECT data_json FROM nodes_v2 WHERE id = ?`, id).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contractnode.Node{}, fmt.Errorf("%w: node %s not found", ErrNotFound, id)
	case err != nil:
		return contractnode.Node{}, fmt.Errorf("query node contract %q failed: %w", id, err)
	}
	return decodeNodeContract(dataJSON)
}

func decodeNodeContract(dataJSON string) (contractnode.Node, error) {
	var node contractnode.Node
	if err := json.Unmarshal([]byte(dataJSON), &node); err != nil {
		return contractnode.Node{}, fmt.Errorf("decode node contract failed: %w", err)
	}
	if err := node.Validate(); err != nil {
		return contractnode.Node{}, err
	}
	return node, nil
}

func chainTypes(chain []contractnode.Protocol) []string {
	out := make([]string, 0, len(chain))
	for _, protocol := range chain {
		out = append(out, protocol.Type)
	}
	return out
}
