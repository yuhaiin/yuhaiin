package kvjson

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

type Store struct {
	path     string
	lockPath string
}

func New(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
			return nil, err
		}
	}

	return &Store{
		path:     path,
		lockPath: path + ".lock",
	}, nil
}

func (s *Store) Get(key string) (any, bool, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, false, err
	}

	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false, err
	}

	v, ok := m[key]
	return v, ok, nil
}

func (s *Store) Set(ctx context.Context, key string, value any) error {
	lock, err := acquireLock(ctx, s.lockPath)
	if err != nil {
		return err
	}
	defer lock.release()

	m, err := s.readAll()
	if err != nil {
		return err
	}

	m[key] = value
	return atomicWriteJSON(s.path, m)
}

func (s *Store) Delete(ctx context.Context, key string) error {
	lock, err := acquireLock(ctx, s.lockPath)
	if err != nil {
		return err
	}
	defer lock.release()

	m, err := s.readAll()
	if err != nil {
		return err
	}

	delete(m, key)
	return atomicWriteJSON(s.path, m)
}

func (s *Store) readAll() (map[string]any, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}

	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func atomicWriteJSON(path string, data map[string]any) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".kvjson-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), path)
}
