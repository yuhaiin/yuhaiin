package configbackup

import (
	"context"
	"database/sql"
	"errors"
	"slices"
)

var sourceURLTables = []string{"route_lists", "route_lists_v2", "route_registries", "settings_kv", "dns_resolvers", "resolvers_v2", "outbound_selectors", "node_monitoring_settings", "backup_settings"}

func ValidateSourceURLRow(table string, columns []string, values []any) error {
	if !slices.Contains(sourceURLTables, table) {
		return nil
	}
	text := func(column string) (string, error) {
		index := slices.Index(columns, column)
		if index < 0 {
			return "", errors.New("invalid configuration source schema")
		}
		switch value := values[index].(type) {
		case string:
			return value, nil
		case []byte:
			return string(value), nil
		default:
			return "", errors.New("invalid configuration source value")
		}
	}
	var document string
	switch table {
	case "route_registries":
		raw, err := text("url")
		if err != nil {
			return err
		}
		return SourceURL(raw)
	case "outbound_selectors":
		var err error
		document, err = text("policy_json")
		if err != nil {
			return err
		}
	case "settings_kv":
		section, err := text("section")
		if err != nil {
			return err
		}
		key, err := text("key")
		if err != nil {
			return err
		}
		if section != "route_extra" || key != "maxminddb_geoip" {
			return nil
		}
		document, err = text("value_json")
		if err != nil {
			return err
		}
	default:
		if table == "dns_resolvers" || table == "resolvers_v2" {
			host, err := text("host")
			if err != nil {
				return err
			}
			if err := SourceURL(host); err != nil {
				return err
			}
		}
		var err error
		document, err = text("data_json")
		if err != nil {
			return err
		}
	}
	return SourceDocument(document)
}

func ValidateSnapshotSourceURLs(ctx context.Context, tx *sql.Tx) error {
	for _, table := range sourceURLTables {
		if err := validateSnapshotSourceTable(ctx, tx, table); err != nil {
			return err
		}
	}
	return nil
}

func validateSnapshotSourceTable(ctx context.Context, tx *sql.Tx, table string) error {
	rows, err := tx.QueryContext(ctx, "SELECT * FROM "+table)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		values, pointers := make([]any, len(columns)), make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return err
		}
		if err := ValidateSourceURLRow(table, columns, values); err != nil {
			return err
		}
	}
	return rows.Err()
}
