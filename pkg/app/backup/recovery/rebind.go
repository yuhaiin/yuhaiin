package recovery

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"

	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	inboundcontract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	nodecontract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/nebula"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/zerotier"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

func rewriteRecoveryConfiguration(ctx context.Context, stage, instanceID string, inputs *contractrecovery.Runtime, resolve func(string) (string, error), mode string) error {
	db, err := sqlite.Open(ctx, filepath.Join(stage, "state.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	if err := store.NewNodeStore(db.DB()).RangeForRecovery(ctx, func(nodecontract.Node) error { return nil }); err != nil {
		return err
	}
	if err := store.NewInboundStore(db.DB()).RangeForRecovery(ctx, func(inboundcontract.Inbound) error { return nil }); err != nil {
		return err
	}
	for _, table := range []string{"nodes_v2", "inbounds_v2", "gateway_configuration"} {
		if err := rewriteRecoveryTable(ctx, db.DB(), table, resolve, mode); err != nil {
			return err
		}
	}
	if mode == "clone" {
		if err := certificates.New(db.DB()).PrepareClone(ctx); err != nil {
			return err
		}
		if _, err := db.DB().ExecContext(ctx, "DELETE FROM gateway_ca"); err != nil {
			return err
		}
		backups := backupstore.New(db.DB())
		options, err := backups.Get(ctx)
		if err != nil {
			return err
		}
		options.InstanceName, options.LastBackupHash, options.Interval = instanceID, "", 0
		options.S3.Enabled, options.S3.AccessKey, options.S3.SecretKey = false, "", ""
		if options.Recovery != nil {
			options.Recovery.Enabled, options.Recovery.AllowMaintenance = false, false
		}
		if err := backups.Save(ctx, options); err != nil {
			return err
		}
		monitoring := store.NewMonitoringStore(db.DB())
		configuration, err := monitoring.Get(ctx)
		if err != nil {
			return err
		}
		configuration.Probe.Enabled, configuration.Speed.Enabled = false, false
		if configuration.UploadSpeed != nil {
			configuration.UploadSpeed.Enabled = false
		}
		if err := disableClonedSelectorMonitoring(ctx, db.DB()); err != nil {
			return err
		}
		if err := monitoring.Save(ctx, configuration); err != nil {
			return err
		}
		inputs.ManagementAuth = true
		if _, err := db.DB().ExecContext(ctx, "DELETE FROM backup_recovery_history"); err != nil {
			return err
		}
		if _, err := db.DB().ExecContext(ctx, "DELETE FROM backup_recovery_imports"); err != nil {
			return err
		}
	}
	if _, err := db.DB().ExecContext(ctx, "UPDATE metadata SET value=? WHERE key='recovery_instance_id'", instanceID); err != nil {
		return err
	}
	if err := backupstore.New(db.DB()).RecordRecoveryRuntime(ctx, *inputs); err != nil {
		return err
	}
	management := filepath.Join(stage, "management.db")
	if mode == "clone" {
		if err := os.Remove(management); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if _, err := os.Stat(management); err == nil || mode == "clone" {
		identity, err := sqlite.OpenManagement(ctx, management)
		if err != nil {
			return err
		}
		return identity.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// A selector override can run even with global monitoring disabled. Rewrite only
// the isolated staged database, without using live CRUD which rejects the clone's
// deliberately disabled candidate nodes. Preserve nil/manual policies and limits.
func disableClonedSelectorMonitoring(ctx context.Context, db *sql.DB) error {
	last, first := "", true
	for {
		query := "SELECT id,policy_json FROM outbound_selectors"
		var parameters []any
		if !first {
			query += " WHERE id>?"
			parameters = []any{last}
		}
		var id, raw string
		err := db.QueryRowContext(ctx, query+" ORDER BY id LIMIT 1", parameters...).Scan(&id, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var policy *nodecontract.SelectorPolicy
		if err := json.Unmarshal([]byte(raw), &policy); err != nil {
			return err
		}
		changed := false
		if policy != nil {
			if policy.Probe != nil && policy.Probe.Enabled {
				policy.Probe.Enabled, changed = false, true
			}
			for _, schedule := range []*nodecontract.SpeedSchedule{policy.PeriodicSpeed, policy.PeriodicUpload} {
				if schedule != nil && schedule.Enabled {
					schedule.Enabled, changed = false, true
				}
			}
		}
		if changed {
			data, err := json.Marshal(policy)
			if err != nil {
				return err
			}
			if _, err := db.ExecContext(ctx, "UPDATE outbound_selectors SET policy_json=?,revision=revision+1 WHERE id=?", string(data), id); err != nil {
				return err
			}
		}
		last, first = id, false
	}
}

func rewriteRecoveryTable(ctx context.Context, db *sql.DB, table string, resolve func(string) (string, error), mode string) error {
	// Keyset iteration releases each cursor before writing on the single
	// connection and retains only one configuration document in memory.
	last, first := "", true
	for {
		var id, raw string
		query := "SELECT id,data_json FROM " + table
		var parameters []any
		if !first {
			query += " WHERE id>?"
			parameters = []any{last}
		}
		err := db.QueryRowContext(ctx, query+" ORDER BY id LIMIT 1", parameters...).Scan(&id, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		var document any
		if err := json.Unmarshal([]byte(raw), &document); err != nil {
			return errors.New("invalid recovery configuration document")
		}
		if err := rebindRecoveryDocument(document, resolve, mode); err != nil {
			return err
		}
		data, err := json.Marshal(document)
		if err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, "UPDATE "+table+" SET data_json=? WHERE id=?", string(data), id); err != nil {
			return err
		}
		last, first = id, false
	}
	if mode == "clone" && table != "gateway_configuration" {
		_, err := db.ExecContext(ctx, "UPDATE "+table+" SET enabled=0")
		return err
	}
	return nil
}

func rebindRecoveryDocument(value any, resolve func(string) (string, error), mode string) error {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			text, isString := child.(string)
			if mode == "clone" && isString && key == "secretKey" {
				// WireGuard/Amnezia local private keys identify a machine. A
				// clone needs a distinct key and server-side peer enrollment.
				var private [32]byte
				if _, err := rand.Read(private[:]); err != nil {
					return err
				}
				private[0] &= 248
				private[31] = (private[31] & 127) | 64
				value[key] = base64.StdEncoding.EncodeToString(private[:])
			} else if isString && text != "" && isRecoveryFileReference(key) {
				mapped, err := resolve(text)
				if err != nil {
					return err
				}
				value[key] = mapped
			} else if isString && key == "config_yaml" {
				mapped, err := nebula.RebindRecoveryFiles(text, resolve)
				if err != nil {
					return err
				}
				value[key] = mapped
			}
			if mode == "clone" && key == "enabled" {
				value[key] = false
			}
			if err := rebindRecoveryDocument(child, resolve, mode); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := rebindRecoveryDocument(child, resolve, mode); err != nil {
				return err
			}
		}
	}
	return nil
}

func recoveryIdentityReplacements(ctx context.Context, stage, target string) ([]string, error) {
	db, err := sqlite.OpenSnapshotReader(ctx, filepath.Join(stage, "state.db"))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var removals []string
	var walk func([]nodecontract.Protocol) error
	walk = func(chain []nodecontract.Protocol) error {
		for _, protocol := range chain {
			var files []string
			var err error
			if protocol.Tailscale != nil {
				files, err = tailscale.RecoveryFiles(target, *protocol.Tailscale)
			} else if protocol.ZeroTier != nil {
				files, err = zerotier.RecoveryFiles(target, *protocol.ZeroTier)
			}
			if err != nil {
				return err
			}
			for _, file := range files {
				if len(removals) >= backuparchive.MaxFiles {
					return errors.New("too many existing protocol identity files to replace")
				}
				relative, err := filepath.Rel(target, file)
				if err != nil || !filepath.IsLocal(relative) {
					return errors.New("protocol identity escaped recovery target")
				}
				removals = append(removals, filepath.ToSlash(relative))
			}
			if protocol.NetworkSplit != nil {
				for _, child := range []*nodecontract.Protocol{protocol.NetworkSplit.TCP, protocol.NetworkSplit.UDP} {
					if child != nil {
						if err := walk([]nodecontract.Protocol{*child}); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	}
	err = store.NewNodeStore(db).RangeForRecovery(ctx, func(node nodecontract.Node) error { return walk(node.Chain) })
	return removals, err
}
