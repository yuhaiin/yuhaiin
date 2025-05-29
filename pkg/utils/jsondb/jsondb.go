// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package jsondb provides a trivial "database": a Go object saved to
// disk as JSON.
package jsondb

import (
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicfile"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// DB is a database backed by a JSON file.
type DB[T proto.Message] struct {
	// Data is the contents of the database.
	Data T

	path string
}

// Open opens the database at path, creating it with a zero value if
// necessary.
func Open[T interface {
	proto.Message
	*A
}, A any](path string, defaultValue T) *DB[T] {
	val := T(new(A))

	bs, err := os.ReadFile(path)
	if err == nil {
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(bs, val)
		if err != nil {
			log.Warn("proto json unmarshal failed", "err", err)
		}
	} else {
		log.Warn("open jsonDB file failed", "path", path, "err", err)
	}

	MergeDefault(val.ProtoReflect(), defaultValue.ProtoReflect())

	return &DB[T]{
		Data: val,
		path: path,
	}
}

func MergeDefault(src, def protoreflect.Message) {
	for fd, v := range def.Range {
		vi, vok := v.Interface().(protoreflect.Message)

		if src.IsValid() && !src.Has(fd) && vok {
			src.Set(fd, v)
		}

		sv := src.Get(fd)

		svi, sok := sv.Interface().(protoreflect.Message)

		if sok && vok {
			MergeDefault(svi, vi)
		}
	}
}

func (db *DB[T]) Dir() string { return filepath.Dir(db.path) }

// Save writes db.Data back to disk.
func (db *DB[T]) Save() error {
	bs, err := protojson.MarshalOptions{Multiline: true, Indent: "\t", EmitUnpopulated: true}.Marshal(db.Data)
	if err != nil {
		return err
	}

	return atomicfile.WriteFile(db.path, bs, 0600)
}
