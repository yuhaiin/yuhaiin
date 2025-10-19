package chore

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
)

type DB interface {
	// Batch modify setting and save
	Batch(f ...func(*config.Setting) error) error
	// View read only
	View(f ...func(*config.Setting) error) error
	// Dir dir of the all data files
	Dir() string
}

var _ DB = (*JsonDB)(nil)

type JsonDB struct {
	path string
	mu   sync.RWMutex
}

func NewJsonDB(path string) *JsonDB { return &JsonDB{path: path} }

func (c *JsonDB) View(f ...func(*config.Setting) error) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// ! for save memory on lowmemory device, we open db every time
	db := jsondb.Open(c.path, config.DefaultSetting(c.path))

	for _, v := range f {
		if err := v(db.Data); err != nil {
			return err
		}
	}

	return nil
}

func (c *JsonDB) Batch(f ...func(*config.Setting) error) error {
	if len(f) == 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// ! for save memory on lowmemory device, we open db every time
	db := jsondb.Open(c.path, config.DefaultSetting(c.path))
	for _, v := range f {
		if err := v(db.Data); err != nil {
			return err
		}
	}

	if err := db.Save(); err != nil {
		return fmt.Errorf("save settings failed: %w", err)
	}

	return nil
}

func (c *JsonDB) Dir() string { return filepath.Dir(c.path) }

func GetSystemHttpHost(s *config.Setting) string {
	if !s.GetSystemProxy().GetHttp() {
		return ""
	}

	for _, v := range s.GetServer().GetInbounds() {
		if !v.GetEnabled() || v.GetTcpudp() == nil {
			continue
		}

		if v.GetHttp() != nil || v.GetMix() != nil {
			return v.GetTcpudp().GetHost()
		}
	}

	return ""
}

func GetSystemSocks5Host(s *config.Setting) string {
	if !s.GetSystemProxy().GetSocks5() {
		return ""
	}

	for _, v := range s.GetServer().GetInbounds() {
		if !v.GetEnabled() || v.GetTcpudp() == nil {
			continue
		}

		if v.GetSocks5() != nil || v.GetMix() != nil {
			return v.GetTcpudp().GetHost()
		}
	}

	return ""
}
