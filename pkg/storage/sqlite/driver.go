package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"

	nativesqlite "github.com/yuhaiin/purego-sqlite"
)

const (
	backendName = "github.com/yuhaiin/purego-sqlite"
	driverName  = "yuhaiin-sqlite"
)

func init() { sql.Register(driverName, sqliteDriver{}) }

// Keep every sql.Open path, including immutable snapshot readers, on the same
// library selection. Native extraction is verified and cached by sqliteembed.
type sqliteDriver struct{}

func (d sqliteDriver) Open(name string) (driver.Conn, error) {
	c, err := d.OpenConnector(name)
	if err != nil {
		return nil, err
	}
	return c.Connect(context.Background())
}

func (sqliteDriver) OpenConnector(name string) (driver.Connector, error) {
	options, err := sqliteOptions()
	if err != nil {
		return nil, err
	}
	return nativesqlite.NewConnector(name, options...)
}

func restrictBackupSnapshot(conn *sql.Conn) error {
	return conn.Raw(func(value any) error {
		c, ok := value.(*nativesqlite.Conn)
		if !ok {
			return errors.New("unexpected SQLite snapshot connection")
		}
		for _, limit := range []struct {
			category nativesqlite.LimitCategory
			value    int
		}{
			{nativesqlite.LimitLength, 64 << 20},
			{nativesqlite.LimitSQLLength, 1 << 20},
			{nativesqlite.LimitExprDepth, 64},
		} {
			if _, err := c.SetLimit(limit.category, limit.value); err != nil {
				return err
			}
		}
		return nil
	})
}

func sqliteErrorDetails(err error) string {
	sqliteErr, ok := errors.AsType[*nativesqlite.Error](err)
	if !ok {
		return ""
	}
	return fmt.Sprintf(" (code=%d extended_code=%d)", sqliteErr.Code, sqliteErr.ExtendedCode)
}

// openConfiguredStore is called only after the read-only schema preflight. Init
// reapplies connection-local settings whenever database/sql replaces a handle.
func openConfiguredStore(path, schema string) (*sql.DB, error) {
	options, err := sqliteOptions()
	if err != nil {
		return nil, err
	}
	pragmas := sqlitePragmas()
	if schema == "management" {
		pragmas = append(pragmas, "PRAGMA synchronous = FULL")
	}
	options = append(options, nativesqlite.WithInit(func(ctx context.Context, conn *nativesqlite.Conn) error {
		for _, statement := range pragmas {
			if _, err := conn.ExecContext(ctx, statement, nil); err != nil {
				return fmt.Errorf("configure sqlite with %q failed: %w", statement, err)
			}
		}
		return nil
	}))
	connector, err := nativesqlite.NewConnector(path, options...)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}
