// Package compatibility validates checksum-bound release schema manifests without
// executing a prospective binary or changing database state.
package compatibility

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

const MaxManifestBytes = 512 << 10
const MaxBinaryBytes = 512 << 20
const Suffix = ".update.json"

type Manifest struct {
	Format       string                                  `json:"format"`
	Version      int                                     `json:"version"`
	Asset        string                                  `json:"asset"`
	SHA256       string                                  `json:"sha256"`
	Size         int64                                   `json:"size"`
	Platform     string                                  `json:"platform"`
	Architecture string                                  `json:"architecture"`
	StartupGuard int                                     `json:"startupGuard"`
	Schemas      map[string][]sqlite.MigrationDescriptor `json:"schemas"`
}

func Describe(ctx context.Context, path, platform, architecture string) (Manifest, error) {
	m := Manifest{Format: "yuhaiin-update", Version: 1, Asset: filepath.Base(path), Platform: platform, Architecture: architecture, StartupGuard: 1, Schemas: make(map[string][]sqlite.MigrationDescriptor)}
	for _, kind := range []string{"configuration", "management"} {
		catalog, err := sqlite.MigrationCatalog(kind)
		if err != nil {
			return m, err
		}
		m.Schemas[kind] = catalog
	}
	file, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxBinaryBytes {
		return m, errors.New("invalid update binary size/type")
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return m, err
		}
		n, err := file.Read(buffer)
		if n > 0 {
			m.Size += int64(n)
			if m.Size > info.Size() {
				return m, errors.New("update binary grew during inspection")
			}
			_, _ = hash.Write(buffer[:n])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, err
		}
	}
	after, err := file.Stat()
	if err != nil || m.Size != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return m, errors.New("update binary changed during inspection")
	}
	m.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return m, m.Validate()
}

func Parse(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) > MaxManifestBytes {
		return m, errors.New("update compatibility manifest exceeds limit")
	}
	if err := json.Unmarshal(data, &m, json.RejectUnknownMembers(true)); err != nil {
		return m, errors.New("invalid update compatibility manifest")
	}
	return m, m.Validate()
}

func (m Manifest) Validate() error {
	if m.Format != "yuhaiin-update" || m.Version != 1 || m.StartupGuard != 1 || m.Size < 1 || m.Size > MaxBinaryBytes || m.Asset == "" || filepath.Base(m.Asset) != m.Asset || strings.ContainsAny(m.Asset, "/\\\x00") || len(m.Asset) > 128 {
		return errors.New("unsupported update compatibility manifest")
	}
	if !validDigest(m.SHA256) {
		return errors.New("invalid update binary digest")
	}
	if !slices.Contains([]string{"linux", "windows", "darwin", "freebsd", "openbsd", "android"}, m.Platform) || !slices.Contains([]string{"amd64", "amd64v3", "amd64v4", "arm64", "mipsle"}, m.Architecture) {
		return errors.New("unsupported update platform")
	}
	if len(m.Schemas) != 2 {
		return errors.New("update manifest must describe both database owners")
	}
	for _, kind := range []string{"configuration", "management"} {
		catalog := m.Schemas[kind]
		if len(catalog) == 0 || len(catalog) > 512 {
			return errors.New("invalid update migration catalog")
		}
		previous := 0
		for _, item := range catalog {
			if item.Version <= previous || len(item.Name) == 0 || len(item.Name) > 256 || !validDigest(item.SHA256) {
				return errors.New("invalid update migration descriptor")
			}
			previous = item.Version
		}
	}
	return nil
}
func validDigest(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == sha256.Size && hex.EncodeToString(data) == value
}

func (m Manifest) Check(ctx context.Context, directory string) (contract.CompatibilityStatus, error) {
	result := contract.CompatibilityStatus{State: "compatible", Reason: "schema_catalog_matches", TargetConfiguration: m.latest("configuration"), TargetManagement: m.latest("management")}
	if err := m.Validate(); err != nil {
		return contract.CompatibilityStatus{State: "unknown", Reason: "invalid_manifest"}, err
	}
	for _, database := range []struct{ name, kind string }{{"state.db", "configuration"}, {"management.db", "management"}} {
		observed, err := sqlite.InspectStoreCatalog(ctx, filepath.Join(directory, database.name), database.kind)
		if errors.Is(err, os.ErrNotExist) && database.kind == "management" {
			continue
		}
		if err != nil {
			return contract.CompatibilityStatus{State: "incompatible", Reason: "database_schema_unreadable"}, err
		}
		if len(observed) == 0 {
			return contract.CompatibilityStatus{State: "incompatible", Reason: "database_schema_unreadable"}, errors.New("database has no established migration history")
		}
		last := observed[len(observed)-1].Version
		if database.kind == "configuration" {
			result.CurrentConfiguration = last
		} else {
			result.CurrentManagement = last
		}
		target := m.Schemas[database.kind]
		if len(observed) > len(target) || !slices.Equal(observed, target[:min(len(observed), len(target))]) {
			result.State, result.Reason = "incompatible", "target_schema_mismatch"
			return result, nil
		}
		if len(observed) < len(target) {
			result.State, result.Reason, result.DatabaseRecoveryRequired = "migration_required", "database_recovery_point_required", true
		}
	}
	return result, nil
}
func (m Manifest) latest(kind string) int {
	items := m.Schemas[kind]
	if len(items) == 0 {
		return 0
	}
	return items[len(items)-1].Version
}
