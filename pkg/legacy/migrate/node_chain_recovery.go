package migrate

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	legacynode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

const nodeChainRecoveryDoneKey = "plain_node_chain_recovery_v1_done"

// RecoverLegacyNodeChains restores network_split steps that an earlier plain
// migration dropped when one of its TCP or UDP branches was absent. Only the
// missing network_split step is inserted; existing v2 node steps remain
// authoritative.
func RecoverLegacyNodeChains(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("database is nil")
	}
	done, err := legacyMigrationMarker(ctx, db, nodeChainRecoveryDoneKey)
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node chain recovery: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `SELECT hash, data_json FROM nodes ORDER BY hash`)
	if err != nil {
		return fmt.Errorf("query legacy nodes for chain recovery: %w", err)
	}
	type legacyNode struct {
		id   string
		data string
	}
	var legacyNodes []legacyNode
	for rows.Next() {
		var item legacyNode
		if err := rows.Scan(&item.id, &item.data); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan legacy node for chain recovery: %w", err)
		}
		legacyNodes = append(legacyNodes, item)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy node rows for chain recovery: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy nodes for chain recovery: %w", err)
	}

	for _, item := range legacyNodes {
		var legacy legacynode.Point
		if err := json.Unmarshal([]byte(item.data), &legacy); err != nil {
			return fmt.Errorf("decode legacy node %q for chain recovery: %w", item.id, err)
		}
		if !hasPartialLegacyNetworkSplit(&legacy) {
			continue
		}

		expected, _, err := ConvertLegacyNode(&legacy)
		if err != nil {
			return fmt.Errorf("convert legacy node %q for chain recovery: %w", item.id, err)
		}
		var dataJSON string
		var updatedAt int64
		err = tx.QueryRowContext(ctx, `SELECT data_json, updated_at FROM nodes_v2 WHERE id = ?`, item.id).Scan(&dataJSON, &updatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("query node contract %q for chain recovery: %w", item.id, err)
		}
		var current contractnode.Node
		if err := json.Unmarshal([]byte(dataJSON), &current); err != nil {
			return fmt.Errorf("decode node contract %q for chain recovery: %w", item.id, err)
		}
		if err := current.Validate(); err != nil {
			return fmt.Errorf("validate node contract %q for chain recovery: %w", item.id, err)
		}

		recovered, changed := recoverPartialNetworkSplits(current.Chain, expected.Chain)
		if !changed {
			continue
		}
		current.Chain = recovered
		if updatedAt == 0 {
			updatedAt = time.Now().Unix()
		}
		if err := plainstore.SaveNodeContract(ctx, tx, current, updatedAt); err != nil {
			return fmt.Errorf("save recovered node %q: %w", item.id, err)
		}
		fmt.Printf("plain node migration recovery: %s: restored partial network_split chain step\n", item.id)
	}

	if err := markMigrationDone(ctx, tx, nodeChainRecoveryDoneKey); err != nil {
		return fmt.Errorf("mark node chain recovery done: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit node chain recovery: %w", err)
	}
	return nil
}

func hasPartialLegacyNetworkSplit(point *legacynode.Point) bool {
	if point == nil {
		return false
	}
	for _, protocol := range point.GetProtocols() {
		split := protocol.GetNetworkSplit()
		if split != nil && (split.GetTcp() == nil) != (split.GetUdp() == nil) {
			return true
		}
	}
	return false
}

func recoverPartialNetworkSplits(current, expected []contractnode.Protocol) ([]contractnode.Protocol, bool) {
	recovered := make([]contractnode.Protocol, 0, len(current)+1)
	currentIndex := 0
	for _, protocol := range expected {
		if currentIndex < len(current) && current[currentIndex].Type == protocol.Type {
			recovered = append(recovered, current[currentIndex])
			currentIndex++
			continue
		}
		if protocol.Type == "network_split" && protocol.NetworkSplit != nil && (protocol.NetworkSplit.TCP == nil) != (protocol.NetworkSplit.UDP == nil) {
			recovered = append(recovered, protocol)
		}
	}
	recovered = append(recovered, current[currentIndex:]...)
	return recovered, !reflect.DeepEqual(current, recovered)
}
