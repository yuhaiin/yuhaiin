package migrate

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	legacyconfig "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

const inboundTransportRecoveryDoneKey = "plain_inbound_transport_recovery_v1_done"

// RecoverLegacyInboundTransportsFromConfig restores supported transports that
// old protobuf-shaped SQLite JSON represented as {}. The original config.json
// still retains the concrete oneof key, so this recovery must run during
// startup migration before any inbound listener is created. Removed gRPC
// transports are intentionally not restored.
func RecoverLegacyInboundTransportsFromConfig(ctx context.Context, db *sql.DB, configPath string) error {
	if db == nil {
		return errors.New("database is nil")
	}
	if configPath == "" {
		return nil
	}

	done, err := legacyMigrationMarker(ctx, db, inboundTransportRecoveryDoneKey)
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}

	data, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read legacy config %q for inbound transport recovery: %w", configPath, err)
	}

	var legacyConfig struct {
		Server struct {
			Inbounds map[string]struct {
				Transport []map[string]jsontext.Value `json:"transport"`
			} `json:"inbounds"`
		} `json:"server"`
	}
	if err := json.Unmarshal(data, &legacyConfig); err != nil {
		return fmt.Errorf("decode legacy config %q for inbound transport recovery: %w", configPath, err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin inbound transport recovery: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `SELECT id, data_json, updated_at FROM inbounds_v2 ORDER BY id`)
	if err != nil {
		return fmt.Errorf("query inbound contracts for transport recovery: %w", err)
	}
	type storedInbound struct {
		inbound contract.Inbound
		updated int64
	}
	var stored []storedInbound
	for rows.Next() {
		var dataJSON string
		var updated int64
		var inbound contract.Inbound
		if err := rows.Scan(&inbound.ID, &dataJSON, &updated); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan inbound contract for transport recovery: %w", err)
		}
		if err := json.Unmarshal([]byte(dataJSON), &inbound); err != nil {
			_ = rows.Close()
			return fmt.Errorf("decode inbound %q for transport recovery: %w", inbound.ID, err)
		}
		if err := inbound.Validate(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("validate inbound %q for transport recovery: %w", inbound.ID, err)
		}
		stored = append(stored, storedInbound{inbound: inbound, updated: updated})
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close inbound contract rows for transport recovery: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate inbound contracts for transport recovery: %w", err)
	}

	for _, item := range stored {
		raw, ok := legacyConfig.Server.Inbounds[item.inbound.ID]
		if !ok {
			continue
		}
		recovered, changed, err := recoverLegacyTransports(item.inbound.Transports, raw.Transport)
		if err != nil {
			return fmt.Errorf("recover inbound %q transports from legacy config: %w", item.inbound.ID, err)
		}
		if !changed {
			continue
		}
		item.inbound.Transports = recovered
		updatedAt := item.updated
		if updatedAt == 0 {
			updatedAt = time.Now().Unix()
		}
		if err := plainstore.SaveInboundContract(ctx, tx, item.inbound, updatedAt); err != nil {
			return fmt.Errorf("save recovered inbound %q: %w", item.inbound.ID, err)
		}
		fmt.Printf("plain inbound migration recovery: %s: restored transport chain from legacy config.json\n", item.inbound.ID)
	}

	if err := markMigrationDone(ctx, tx, inboundTransportRecoveryDoneKey); err != nil {
		return fmt.Errorf("mark inbound transport recovery done: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit inbound transport recovery: %w", err)
	}
	return nil
}

func recoverLegacyTransports(current []contract.Transport, raw []map[string]jsontext.Value) ([]contract.Transport, bool, error) {
	if len(raw) == 0 {
		return current, false, nil
	}

	recovered := make([]contract.Transport, 0, len(raw)+len(current))
	currentIndex := 0
	for index, rawTransport := range raw {
		typ := legacyTransportType(rawTransport)
		if typ == "grpc" {
			// gRPC was intentionally removed from the plain model.
			continue
		}
		if typ == "" {
			return nil, false, fmt.Errorf("transport[%d] has no concrete type", index)
		}

		var legacyTransport legacyconfig.Transport
		rawJSON, err := json.Marshal(rawTransport)
		if err != nil {
			return nil, false, fmt.Errorf("encode transport[%d] %q: %w", index, typ, err)
		}
		if err := json.Unmarshal(rawJSON, &legacyTransport); err != nil {
			return nil, false, fmt.Errorf("decode transport[%d] %q: %w", index, typ, err)
		}
		transport, err := convertLegacyTransport(&legacyTransport)
		if err != nil {
			return nil, false, fmt.Errorf("convert transport[%d] %q: %w", index, typ, err)
		}
		if currentIndex < len(current) && current[currentIndex].Type == typ {
			recovered = append(recovered, current[currentIndex])
			currentIndex++
			continue
		}
		recovered = append(recovered, transport)
	}
	recovered = append(recovered, current[currentIndex:]...)
	return recovered, !reflect.DeepEqual(current, recovered), nil
}

func legacyTransportType(raw map[string]jsontext.Value) string {
	if len(raw) != 1 {
		return ""
	}
	for typ := range raw {
		return typ
	}
	return ""
}

func legacyMigrationMarker(ctx context.Context, db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load migration marker %q: %w", key, err)
	}
	return value, nil
}
