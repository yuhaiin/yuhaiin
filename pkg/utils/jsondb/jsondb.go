// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package jsondb provides a trivial "database": a Go object saved to
// disk as JSON.
package jsondb

import (
	"encoding/json/v2"
	"os"
	"reflect"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicfile"
)

// DB is a database backed by a JSON file.
type DB[T any] struct {
	// Data is the contents of the database.
	Data T

	path string
}

// Open opens the database at path, creating it with a zero value if
// necessary.
func Open[T any](path string, defaultValue T) *DB[T] {
	val := clone(defaultValue)

	bs, err := os.ReadFile(path)
	if err == nil {
		if err = json.Unmarshal(bs, val); err != nil {
			log.Warn("json unmarshal failed", "err", err)
		}
	} else {
		log.Warn("open jsonDB file failed", "path", path, "err", err)
	}

	MergeDefault(val, defaultValue)

	return &DB[T]{
		Data: val,
		path: path,
	}
}

func MergeDefault(src, def any) {
	mergeDefaultValue(reflect.ValueOf(src), reflect.ValueOf(def))
}

func mergeDefaultValue(src, def reflect.Value) {
	if !src.IsValid() || !def.IsValid() {
		return
	}

	if src.Kind() == reflect.Interface {
		src = src.Elem()
	}
	if def.Kind() == reflect.Interface {
		def = def.Elem()
	}

	if src.Kind() == reflect.Pointer {
		if def.Kind() == reflect.Pointer {
			if src.IsNil() {
				if !def.IsNil() && src.CanSet() {
					src.Set(cloneValue(def))
				}
				return
			}
			if def.IsNil() {
				return
			}
			mergeDefaultValue(src.Elem(), def.Elem())
			return
		}
		if src.IsNil() {
			return
		}
		mergeDefaultValue(src.Elem(), def)
		return
	}

	if def.Kind() == reflect.Pointer {
		if def.IsNil() {
			return
		}
		mergeDefaultValue(src, def.Elem())
		return
	}

	if src.Kind() != reflect.Struct || def.Kind() != reflect.Struct {
		return
	}

	for i := range src.NumField() {
		sf := src.Field(i)
		df := def.Field(i)
		if !sf.CanSet() && sf.Kind() != reflect.Pointer {
			continue
		}

		switch sf.Kind() {
		case reflect.Pointer:
			if sf.IsNil() {
				if !df.IsNil() && sf.CanSet() {
					sf.Set(cloneValue(df))
				}
				continue
			}
			mergeDefaultValue(sf, df)
		case reflect.Map, reflect.Slice:
			if sf.IsNil() && !df.IsNil() && sf.CanSet() {
				sf.Set(cloneValue(df))
			}
		case reflect.Struct:
			mergeDefaultValue(sf, df)
		}
	}
}

func clone[T any](v T) T {
	var out T
	data, err := json.Marshal(v)
	if err != nil {
		return v
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return v
	}
	return out
}

func cloneValue(v reflect.Value) reflect.Value {
	if !v.IsValid() {
		return v
	}

	out := reflect.New(v.Type())
	data, err := json.Marshal(v.Interface())
	if err != nil {
		return v
	}
	if err := json.Unmarshal(data, out.Interface()); err != nil {
		return v
	}
	return out.Elem()
}

// Save writes db.Data back to disk.
func (db *DB[T]) Save() error {
	bs, err := json.Marshal(db.Data)
	if err != nil {
		return err
	}

	return atomicfile.WriteFile(db.path, bs, 0600)
}
