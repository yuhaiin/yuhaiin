package eap

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// FileStore holds username/password credentials loaded from a file, and
// provides a CredentialLookup for the EAP server.
//
// File format: one "username:password" per line. Blank lines and lines
// beginning with '#' are ignored. Passwords may contain ':' (only the first
// colon separates the fields). Whitespace around the username is trimmed; the
// password is taken verbatim after the first colon.
type FileStore struct {
	mu    sync.RWMutex
	users map[string]string
}

// LoadFileStore reads a credential file into a FileStore.
func LoadFileStore(path string) (*FileStore, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	store := &FileStore{users: make(map[string]string)}
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			return nil, fmt.Errorf("eap: %s:%d: missing ':' separator", path, lineNo)
		}
		user := strings.TrimSpace(line[:idx])
		pass := line[idx+1:]
		if user == "" {
			return nil, fmt.Errorf("eap: %s:%d: empty username", path, lineNo)
		}
		store.users[user] = pass
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return store, nil
}

// NewMemoryStore builds a FileStore from an in-memory map (useful for tests or
// programmatic configuration).
func NewMemoryStore(users map[string]string) *FileStore {
	cp := make(map[string]string, len(users))
	for k, v := range users {
		cp[k] = v
	}
	return &FileStore{users: cp}
}

// Lookup implements CredentialLookup.
func (s *FileStore) Lookup(username string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.users[username]
	return p, ok
}

// Count returns the number of loaded credentials.
func (s *FileStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}
