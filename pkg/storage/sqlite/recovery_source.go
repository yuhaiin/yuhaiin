package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"uuid"

	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
)

const recoveryInstanceKey = "recovery_instance_id"

// RequireClosed supplements the process lifecycle lock for embedded callers.
// It checks physical files as well as paths, so directory aliases do not hide
// a configuration/identity connection owned by this process.
func RequireClosed(paths ...string) error {
	sharedSQLite.Lock()
	defer sharedSQLite.Unlock()
	for _, candidate := range paths {
		absolute, err := canonicalPath(candidate)
		if err != nil {
			return err
		}
		candidateInfo, statErr := os.Stat(absolute)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		for opened, store := range sharedSQLite.stores {
			if store.refs < 1 {
				continue
			}
			if opened == absolute {
				return errors.New("database is still open; stop its owners before maintenance")
			}
			if candidateInfo != nil {
				info, err := os.Stat(opened)
				if err == nil && os.SameFile(candidateInfo, info) {
					return errors.New("database is still open through another path")
				}
			}
		}
	}
	return nil
}

func recoveryDatabaseURI(path, mode string, immutable bool) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	query := url.Values{"mode": {mode}}
	if immutable {
		query.Set("immutable", "1")
	}
	uri := &url.URL{Scheme: "file", Path: filepath.ToSlash(absolute), RawQuery: query.Encode()}
	if filepath.VolumeName(absolute) != "" && !strings.HasPrefix(uri.Path, "/") {
		uri.Path = "/" + uri.Path
	}
	return uri.String(), nil
}

// OpenSnapshotReader exposes an already validated standalone snapshot to the
// existing typed stores without bootstrapping/migrating it or creating WALs.
func OpenSnapshotReader(ctx context.Context, path string) (*sql.DB, error) {
	uri, err := recoveryDatabaseURI(path, "ro", true)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driverName, uri)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, err := db.Conn(ctx)
	if err == nil {
		err = restrictBackupSnapshot(conn)
	}
	if err == nil {
		_, err = conn.ExecContext(ctx, "PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA cache_size=-2048")
	}
	if conn != nil {
		_ = conn.Close()
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// SnapshotRecoveryDatabase captures committed WAL data with SQLite rather than
// copying the main file. Multi-database/file consistency is the maintenance
// owner's responsibility. The source is never migrated or opened writable.
func SnapshotRecoveryDatabase(ctx context.Context, source, destination, kind string, limit int64) (int, error) {
	return SnapshotRecoveryDatabaseWithSpaceCheck(ctx, source, destination, kind, limit, nil)
}

// SnapshotRecoveryDatabaseWithSpaceCheck admits the compacted output against
// the maintenance owner's destination filesystem before VACUUM allocates it.
// It reads the live WAL-aware page inventory, not just the main file's length.
func SnapshotRecoveryDatabaseWithSpaceCheck(ctx context.Context, source, destination, kind string, limit int64, checkSpace func(int64) error) (int, error) {
	if limit < 1 || limit > contractrecovery.MaxDataBytes {
		return 0, errors.New("invalid recovery database budget")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("recovery database source must be a regular file")
	}
	if _, err := os.Lstat(destination); err == nil {
		return 0, errors.New("recovery snapshot destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	uri, err := recoveryDatabaseURI(source, "ro", false)
	if err != nil {
		return 0, err
	}
	db, err := sql.Open(driverName, uri)
	if err != nil {
		return 0, err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := restrictBackupSnapshot(conn); err != nil {
		return 0, err
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF; PRAGMA cache_size=-2048"); err != nil {
		return 0, err
	}
	var pages, pageSize, freePages int64
	if err := conn.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return 0, err
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return 0, err
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freePages); err != nil {
		return 0, err
	}
	if pages < 0 || freePages < 0 || freePages > pages || pageSize <= 0 || pages-freePages > limit/pageSize {
		return 0, errors.New("recovery database exceeds 100 GiB budget")
	}
	if checkSpace != nil {
		if err := checkSpace((pages - freePages) * pageSize); err != nil {
			return 0, err
		}
	}
	if _, err := conn.ExecContext(ctx, "VACUUM INTO ?", destination); err != nil {
		_ = os.Remove(destination)
		return 0, err
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		_ = os.Remove(destination)
		return 0, err
	}
	if info, err := os.Stat(destination); err != nil || info.Size() > limit {
		_ = os.Remove(destination)
		return 0, errors.New("recovery snapshot exceeded its size budget")
	}
	version, err := InspectBackupSnapshot(ctx, destination, kind)
	if err != nil {
		_ = os.Remove(destination)
		return 0, err
	}
	return version, nil
}

// RecoveryInstanceID is called only on a validated store while all writers are
// stopped. The stable UUID is metadata, not an authentication credential.
func RecoveryInstanceID(ctx context.Context, path string, create bool) (string, error) {
	mode := "ro"
	if create {
		mode = "rw"
	}
	uri, err := recoveryDatabaseURI(path, mode, false)
	if err != nil {
		return "", err
	}
	db, err := sql.Open(driverName, uri)
	if err != nil {
		return "", err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if create {
		if _, err := db.ExecContext(ctx, "INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO NOTHING", recoveryInstanceKey, uuid.New().String()); err != nil {
			return "", err
		}
	}
	var id string
	if err := db.QueryRowContext(ctx, "SELECT CASE WHEN typeof(value)='text' AND length(value)=36 THEN value ELSE '' END FROM metadata WHERE key=?", recoveryInstanceKey).Scan(&id); err != nil {
		return "", err
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == (uuid.UUID{}) || parsed.String() != id {
		return "", errors.New("invalid persisted recovery instance identifier")
	}
	return id, nil
}

// BindRecoveryInstance records the source UUID in its new immutable snapshot.
// It does not run configuration migrations or replace an existing identifier.
func BindRecoveryInstance(ctx context.Context, path, id string) error {
	uri, err := recoveryDatabaseURI(path, "rw", false)
	if err != nil {
		return err
	}
	db, err := sql.Open(driverName, uri)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO NOTHING", recoveryInstanceKey, id); err != nil {
		return err
	}
	var stored string
	if err := db.QueryRowContext(ctx, "SELECT CASE WHEN typeof(value)='text' AND length(value)=36 THEN value ELSE '' END FROM metadata WHERE key=?", recoveryInstanceKey).Scan(&stored); err != nil {
		return err
	}
	if stored != id {
		return fmt.Errorf("recovery snapshot instance binding disagrees with source")
	}
	return nil
}
