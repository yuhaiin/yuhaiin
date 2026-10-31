package store

import (
	"bytes"
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	"strconv"
	"time"
)

// UpdateRefreshErrors merges downloaded status without overwriting user edits.
func (s *RouteListStore) UpdateRefreshErrors(ctx context.Context, downloaded contractroute.RouteListDetail) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var data string
	if err := tx.QueryRowContext(ctx, `SELECT data_json FROM route_lists_v2 WHERE id = ?`, downloaded.ID).Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrConflict
		}
		return err
	}
	current, err := decodeRouteListDetail(data)
	if err != nil {
		return err
	}
	before, err := json.Marshal(downloaded.Source)
	if err != nil {
		return err
	}
	after, err := json.Marshal(current.Source)
	if err != nil {
		return err
	}
	if current.Type != downloaded.Type || !bytes.Equal(before, after) {
		return ErrConflict
	}
	current.ErrorMsgs = downloaded.ErrorMsgs
	encoded, err := json.Marshal(current)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE route_lists_v2 SET data_json = ? WHERE id = ?`, string(encoded), current.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *RouteSettingsStore) RecordRefresh(ctx context.Context, refreshed RouteListSettings) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := readRouteListSettings(ctx, tx)
	if err != nil {
		return err
	}
	current.LastRefreshTime = refreshed.LastRefreshTime
	current.Error = refreshed.Error
	if current.MaxMindDBDownloadURL == refreshed.MaxMindDBDownloadURL {
		current.MaxMindDBError = refreshed.MaxMindDBError
	}
	if err := saveRouteListSettings(ctx, tx, current, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *RouteSettingsStore) SaveListConfig(ctx context.Context, config contractroute.ListConfig, interval uint64) (RouteListSettings, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RouteListSettings{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := readRouteListSettings(ctx, tx)
	if err != nil {
		return current, err
	}
	previous := contractroute.ListConfig{Revision: current.Revision, RefreshInterval: strconv.FormatUint(current.RefreshInterval, 10), LastRefreshTime: strconv.FormatUint(current.LastRefreshTime, 10), Error: current.Error, HostIndexDisk: current.HostIndexDisk, MaxMindDBGeoIP: contractroute.MaxMindDBGeoIP{DownloadURL: current.MaxMindDBDownloadURL, Error: current.MaxMindDBError}}
	config, err = secret.Merge(ctx, config, previous)
	if err != nil {
		return current, err
	}
	if config.Revision != current.Revision {
		return current, ErrConflict
	}
	current.Revision++
	current.RefreshInterval = interval
	current.HostIndexDisk = config.HostIndexDisk
	if current.MaxMindDBDownloadURL != config.MaxMindDBGeoIP.DownloadURL {
		current.MaxMindDBDownloadURL = config.MaxMindDBGeoIP.DownloadURL
		current.MaxMindDBError = ""
	}
	if err := saveRouteListSettings(ctx, tx, current, time.Now().Unix()); err != nil {
		return current, err
	}
	return current, tx.Commit()
}
