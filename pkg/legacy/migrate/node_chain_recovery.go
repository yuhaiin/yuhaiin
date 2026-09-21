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
	type recoveryNode struct {
		id       string
		expected contractnode.Node
	}
	var recoveryNodes []recoveryNode
	for rows.Next() {
		var id, data string
		if err := rows.Scan(&id, &data); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan legacy node for chain recovery: %w", err)
		}
		var legacy legacynode.Point
		if err := json.Unmarshal([]byte(data), &legacy); err != nil {
			_ = rows.Close()
			return fmt.Errorf("decode legacy node %q for chain recovery: %w", id, err)
		}
		if !hasPartialLegacyNetworkSplit(&legacy) {
			continue
		}

		expected, _, err := ConvertLegacyNode(&legacy)
		if err != nil {
			_ = rows.Close()
			return fmt.Errorf("convert legacy node %q for chain recovery: %w", id, err)
		}
		recoveryNodes = append(recoveryNodes, recoveryNode{id: id, expected: expected})
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy node rows for chain recovery: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy nodes for chain recovery: %w", err)
	}

	for _, item := range recoveryNodes {
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

		recovered, changed := recoverPartialNetworkSplits(current.Chain, item.expected.Chain)
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
	recovered := append([]contractnode.Protocol(nil), current...)
	splitCount := 0
	for _, protocol := range current {
		if protocol.Type == "network_split" {
			splitCount++
		}
	}

	seenExpected := 0
	for index, protocol := range expected {
		if !isPartialNetworkSplit(protocol) {
			continue
		}
		seenExpected++
		if splitCount >= seenExpected {
			continue
		}

		// Insert before the next expected step that is already present. This
		// preserves the complete v2 sequence, including steps that the legacy
		// conversion did not know about, instead of aligning by raw indexes.
		insertAt := len(recovered)
		for _, next := range expected[index+1:] {
			if isPartialNetworkSplit(next) {
				continue
			}
			if position := findProtocolType(recovered, next.Type); position >= 0 {
				insertAt = position
				break
			}
		}
		recovered = insertProtocol(recovered, insertAt, protocol)
		splitCount++
	}
	return recovered, !reflect.DeepEqual(current, recovered)
}

func isPartialNetworkSplit(protocol contractnode.Protocol) bool {
	return protocol.Type == "network_split" && protocol.NetworkSplit != nil &&
		(protocol.NetworkSplit.TCP == nil) != (protocol.NetworkSplit.UDP == nil)
}

func findProtocolType(protocols []contractnode.Protocol, typ string) int {
	for index, protocol := range protocols {
		if protocol.Type == typ {
			return index
		}
	}
	return -1
}

func insertProtocol(protocols []contractnode.Protocol, index int, protocol contractnode.Protocol) []contractnode.Protocol {
	if index < 0 || index > len(protocols) {
		index = len(protocols)
	}
	protocols = append(protocols, contractnode.Protocol{})
	copy(protocols[index+1:], protocols[index:])
	protocols[index] = protocol
	return protocols
}
