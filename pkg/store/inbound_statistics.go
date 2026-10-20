package store

import (
	"context"
	"errors"
	"math"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
)

// LoadIngressStatistics restores counters by stable inbound ID. These counters
// deliberately do not share the listener's transient running/failed state.
func (s *InboundStore) LoadIngressStatistics(ctx context.Context) (map[string]contract.IngressTotals, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("inbound store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT inbound_id,accepted_streams,received_packets,received_pings FROM inbound_statistics`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make(map[string]contract.IngressTotals)
	for rows.Next() {
		var id string
		var streams, packets, pings int64
		if err := rows.Scan(&id, &streams, &packets, &pings); err != nil {
			return nil, err
		}
		if streams < 0 || packets < 0 || pings < 0 {
			return nil, errors.New("negative inbound ingress statistics")
		}
		values[id] = contract.IngressTotals{
			AcceptedStreams: uint64(streams),
			ReceivedPackets: uint64(packets),
			ReceivedPings:   uint64(pings),
		}
	}
	return values, rows.Err()
}

func ingressStatInt(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

// SaveIngressStatistics stores absolute counter snapshots in one transaction.
// Repeated flushes are idempotent, and deleted inbounds cannot be recreated
// through a delayed writer (the SELECT requires an existing owner).
func (s *InboundStore) SaveIngressStatistics(ctx context.Context, values map[string]contract.IngressTotals) error {
	if s == nil || s.db == nil {
		return errors.New("inbound store database is nil")
	}
	if len(values) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO inbound_statistics
		(inbound_id,accepted_streams,received_packets,received_pings,updated_at)
		SELECT ?,?,?,?,?
		WHERE EXISTS (SELECT 1 FROM inbounds_v2 WHERE id=?)
		ON CONFLICT(inbound_id) DO UPDATE SET
		accepted_streams=excluded.accepted_streams,
		received_packets=excluded.received_packets,
		received_pings=excluded.received_pings,
		updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	for id, value := range values {
		if _, err := stmt.ExecContext(ctx, id, ingressStatInt(value.AcceptedStreams),
			ingressStatInt(value.ReceivedPackets), ingressStatInt(value.ReceivedPings),
			now, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
