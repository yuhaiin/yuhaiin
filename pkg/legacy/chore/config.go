package chore

import (
	"context"
	"database/sql"

	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
)

type DB interface {
	// Batch modify setting and save
	Batch(f ...func(*config.Setting) error) error
	// View read only
	View(f ...func(*config.Setting) error) error
	// Dir dir of the all data files
	Dir() string
}

type SQLStore interface {
	SQLDB(context.Context) (*sql.DB, error)
}

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
