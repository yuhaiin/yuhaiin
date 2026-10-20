package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	json "encoding/json/v2"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

var ErrNotFound = errors.New("not found")

type InboundStore struct {
	db *sql.DB
}

type InboundExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func NewInboundStore(db *sql.DB) *InboundStore {
	return &InboundStore{db: db}
}

func (s *InboundStore) Save(ctx context.Context, inbound contract.Inbound, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("inbound store database is nil")
	}
	if err := inbound.Validate(); err != nil {
		return err
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	return SaveInboundContract(ctx, s.db, inbound, updatedAt)
}

func SaveInboundContract(ctx context.Context, execer InboundExecer, inbound contract.Inbound, updatedAt int64) error {
	if err := inbound.Validate(); err != nil {
		return err
	}
	transportTypes := make([]string, 0, len(inbound.Transports))
	for _, transport := range inbound.Transports {
		transportTypes = append(transportTypes, transport.Type)
	}
	transportTypesJSON, err := json.Marshal(transportTypes)
	if err != nil {
		return fmt.Errorf("encode inbound transport types failed: %w", err)
	}
	dataJSON, err := json.Marshal(inbound)
	if err != nil {
		return fmt.Errorf("encode inbound %q failed: %w", inbound.ID, err)
	}

	if _, err := execer.ExecContext(ctx, `
		INSERT INTO inbounds_v2(
			id,
			name,
			enabled,
			network_type,
			protocol_type,
			transport_types_json,
			updated_at,
			data_json
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			enabled = excluded.enabled,
			network_type = excluded.network_type,
			protocol_type = excluded.protocol_type,
			transport_types_json = excluded.transport_types_json,
			updated_at = excluded.updated_at,
			data_json = excluded.data_json
	`, inbound.ID, inbound.Name, boolToInt(inbound.Enabled), inbound.Network.Type, inbound.Protocol.Type, string(transportTypesJSON), updatedAt, string(dataJSON)); err != nil {
		return fmt.Errorf("save inbound %q failed: %w", inbound.ID, err)
	}
	return nil
}

func (s *InboundStore) Get(ctx context.Context, id string) (contract.Inbound, error) {
	if s == nil || s.db == nil {
		return contract.Inbound{}, errors.New("inbound store database is nil")
	}

	var dataJSON string
	err := s.db.QueryRowContext(ctx, `
		SELECT data_json
		FROM inbounds_v2
		WHERE id = ?
	`, id).Scan(&dataJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return contract.Inbound{}, fmt.Errorf("%w: inbound %s", ErrNotFound, id)
	}
	if err != nil {
		return contract.Inbound{}, fmt.Errorf("query inbound %q failed: %w", id, err)
	}

	return decodeInbound(dataJSON)
}

func (s *InboundStore) List(ctx context.Context) ([]contract.Inbound, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("inbound store database is nil")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, data_json
		FROM inbounds_v2
		ORDER BY name, id
	`)
	if err != nil {
		return nil, fmt.Errorf("query inbounds failed: %w", err)
	}
	defer rows.Close()

	var inbounds []contract.Inbound
	for rows.Next() {
		var id, dataJSON string
		if err := rows.Scan(&id, &dataJSON); err != nil {
			return nil, fmt.Errorf("scan inbound failed: %w", err)
		}
		inbound, err := decodeInbound(dataJSON)
		if err != nil {
			log.Warn("skip invalid stored inbound", "id", id, "err", err)
			continue
		}
		inbounds = append(inbounds, inbound)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate inbounds failed: %w", err)
	}
	return inbounds, nil
}

func (s *InboundStore) Delete(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return errors.New("inbound store database is nil")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	refs, err := InboundReferences(ctx, tx, id)
	if err != nil {
		return err
	}
	if len(refs) > 0 {
		return &ResourceInUseError{References: refs}
	}
	result, err := tx.ExecContext(ctx, `
		DELETE FROM inbounds_v2
		WHERE id = ?
	`, id)
	if err != nil {
		return fmt.Errorf("delete inbound %q failed: %w", id, err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("%w: inbound %s", ErrNotFound, id)
	}
	// Statistics are runtime data and not part of config backups. A real
	// inbound deletion, however, removes its counters in this transaction.
	if _, err := tx.ExecContext(ctx, `DELETE FROM inbound_statistics WHERE inbound_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func decodeInbound(dataJSON string) (contract.Inbound, error) {
	var inbound contract.Inbound
	if err := json.Unmarshal([]byte(dataJSON), &inbound); err != nil {
		return contract.Inbound{}, fmt.Errorf("decode inbound failed: %w", err)
	}
	// Reads retain unsupported protocol/network/transport tags so management can
	// show and remove old configurations. Saving and activation validate them.
	return inbound, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
