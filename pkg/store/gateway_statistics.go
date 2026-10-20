package store

import (
	"context"
	"errors"
	"math"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

func (s *GatewayStore) LoadStatistics(ctx context.Context) (map[string]contract.StatisticsTotals, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT gateway_id,requests,blocked,forwarded,errors,tls_failures,protocol_failures,duration_ns FROM gateway_statistics`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	statistics := make(map[string]contract.StatisticsTotals)
	for rows.Next() {
		var id string
		var requests, blocked, forwarded, failures, tls, protocol, duration int64
		if err := rows.Scan(&id, &requests, &blocked, &forwarded, &failures, &tls, &protocol, &duration); err != nil {
			return nil, err
		}
		if requests < 0 || blocked < 0 || forwarded < 0 || failures < 0 || tls < 0 || protocol < 0 || duration < 0 {
			return nil, errors.New("invalid negative Gateway statistics")
		}
		statistics[id] = contract.StatisticsTotals{
			Requests: uint64(requests), Blocked: uint64(blocked),
			Forwarded: uint64(forwarded), Errors: uint64(failures),
			TLSFailures: uint64(tls), ProtocolFailures: uint64(protocol),
			DurationNS: uint64(duration),
		}
	}
	return statistics, rows.Err()
}

func statisticInt(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

// SaveStatistics upserts absolute cumulative snapshots in one transaction.
// Retrying a failed or interrupted flush cannot double-count requests.
func (s *GatewayStore) SaveStatistics(ctx context.Context, values map[string]contract.StatisticsTotals) error {
	if len(values) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO gateway_statistics
		(gateway_id,requests,blocked,forwarded,errors,tls_failures,protocol_failures,duration_ns,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(gateway_id) DO UPDATE SET
		requests=excluded.requests,blocked=excluded.blocked,
		forwarded=excluded.forwarded,errors=excluded.errors,
		tls_failures=excluded.tls_failures,protocol_failures=excluded.protocol_failures,
		duration_ns=excluded.duration_ns,updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	for id, value := range values {
		if _, err := stmt.ExecContext(ctx, id, statisticInt(value.Requests), statisticInt(value.Blocked),
			statisticInt(value.Forwarded), statisticInt(value.Errors), statisticInt(value.TLSFailures),
			statisticInt(value.ProtocolFailures), statisticInt(value.DurationNS), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *GatewayStore) ResetStatistics(ctx context.Context, id string) error {
	if id == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM gateway_statistics`)
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM gateway_statistics WHERE gateway_id=?`, id)
	return err
}
