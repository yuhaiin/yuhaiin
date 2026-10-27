package backup

import (
	"context"
	"errors"
	"path/filepath"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func inspectRecoveryDatabases(ctx context.Context, directory string, manifest contract.RecoveryManifest) error {
	for _, file := range manifest.Files {
		kind := ""
		switch file.Role {
		case "configuration_database":
			kind = "configuration"
		case "management_database":
			kind = "management"
		default:
			continue
		}
		version, err := sqlite.InspectBackupSnapshot(ctx, filepath.Join(directory, filepath.FromSlash(file.Path)), kind)
		if err != nil {
			return err
		}
		if version != file.SchemaVersion {
			return errors.New("recovery manifest disagrees with actual database schema")
		}
	}
	return nil
}
