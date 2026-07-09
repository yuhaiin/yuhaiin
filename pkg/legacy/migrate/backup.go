package migrate

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	legacyconfig "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func MigrateLegacyBackup(ctx context.Context, db *sql.DB, updatedAt int64) error {
	if db == nil {
		return errors.New("database is nil")
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}

	var dataJSON string
	err := db.QueryRowContext(ctx, `
		SELECT data_json
		FROM backup_settings
		WHERE id = 1
	`).Scan(&dataJSON)
	if errors.Is(err, sql.ErrNoRows) {
		if err := markMigrationDone(ctx, db, "plain_backup_migration_done"); err != nil {
			return fmt.Errorf("mark legacy backup migration done failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("query legacy backup settings failed: %w", err)
	}

	backup, err := convertLegacyBackupJSON([]byte(dataJSON))
	if err != nil {
		return err
	}
	if err := plainstore.NewBackupStore(db).Save(ctx, backup); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `UPDATE backup_settings SET updated_at = ? WHERE id = 1`, updatedAt); err != nil {
		return fmt.Errorf("set backup migration timestamp failed: %w", err)
	}
	if err := markMigrationDone(ctx, db, "plain_backup_migration_done"); err != nil {
		return fmt.Errorf("mark legacy backup migration done failed: %w", err)
	}
	return nil
}

func convertLegacyBackupJSON(data []byte) (contractbackup.Option, error) {
	var legacy legacyconfig.BackupOption
	if err := json.Unmarshal(data, &legacy); err != nil {
		return contractbackup.Option{}, fmt.Errorf("decode legacy backup settings failed: %w", err)
	}

	out := contractbackup.Option{
		InstanceName:   legacy.GetInstanceName(),
		Interval:       legacy.GetInterval(),
		LastBackupHash: legacy.GetLastBackupHash(),
	}
	if legacy.GetS3() != nil {
		out.S3 = contractbackup.S3{
			Enabled:      legacy.GetS3().GetEnabled(),
			AccessKey:    legacy.GetS3().GetAccessKey(),
			SecretKey:    legacy.GetS3().GetSecretKey(),
			Bucket:       legacy.GetS3().GetBucket(),
			Region:       legacy.GetS3().GetRegion(),
			EndpointURL:  legacy.GetS3().GetEndpointUrl(),
			UsePathStyle: legacy.GetS3().GetUsePathStyle(),
			StorageClass: legacy.GetS3().GetStorageClass(),
		}
	}

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return contractbackup.Option{}, fmt.Errorf("decode backup settings object failed: %w", err)
	}
	if s3Raw := rawValue(raw, "s3"); len(s3Raw) != 0 && string(s3Raw) != "null" {
		s3, err := decodeBackupS3(s3Raw)
		if err != nil {
			return contractbackup.Option{}, err
		}
		out.S3 = s3
	}
	return out, nil
}

func decodeBackupS3(data []byte) (contractbackup.S3, error) {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return contractbackup.S3{}, fmt.Errorf("decode backup s3 settings failed: %w", err)
	}
	var out contractbackup.S3
	if err := decodeBool(raw, &out.Enabled, "enabled"); err != nil {
		return contractbackup.S3{}, fmt.Errorf("backup s3 enabled: %w", err)
	}
	if err := decodeString(raw, &out.AccessKey, "access_key", "accessKey"); err != nil {
		return contractbackup.S3{}, fmt.Errorf("backup s3 access_key: %w", err)
	}
	if err := decodeString(raw, &out.SecretKey, "secret_key", "secretKey"); err != nil {
		return contractbackup.S3{}, fmt.Errorf("backup s3 secret_key: %w", err)
	}
	if err := decodeString(raw, &out.Bucket, "bucket"); err != nil {
		return contractbackup.S3{}, fmt.Errorf("backup s3 bucket: %w", err)
	}
	if err := decodeString(raw, &out.Region, "region"); err != nil {
		return contractbackup.S3{}, fmt.Errorf("backup s3 region: %w", err)
	}
	if err := decodeString(raw, &out.EndpointURL, "endpoint_url", "endpointUrl"); err != nil {
		return contractbackup.S3{}, fmt.Errorf("backup s3 endpoint_url: %w", err)
	}
	if err := decodeBool(raw, &out.UsePathStyle, "use_path_style", "usePathStyle"); err != nil {
		return contractbackup.S3{}, fmt.Errorf("backup s3 use_path_style: %w", err)
	}
	if err := decodeString(raw, &out.StorageClass, "storage_class", "storageClass"); err != nil {
		return contractbackup.S3{}, fmt.Errorf("backup s3 storage_class: %w", err)
	}
	return out, nil
}

func decodeString(raw map[string]jsontext.Value, out *string, keys ...string) error {
	value := rawValue(raw, keys...)
	if len(value) == 0 || string(value) == "null" {
		return nil
	}
	return json.Unmarshal(value, out)
}

func decodeBool(raw map[string]jsontext.Value, out *bool, keys ...string) error {
	value := rawValue(raw, keys...)
	if len(value) == 0 || string(value) == "null" {
		return nil
	}
	return json.Unmarshal(value, out)
}

func rawValue(raw map[string]jsontext.Value, keys ...string) jsontext.Value {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			return value
		}
	}
	return nil
}
