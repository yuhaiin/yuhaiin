package compatibility

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func fixture(t *testing.T) (string, Manifest) {
	t.Helper()
	directory := t.TempDir()
	state, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	identity, err := sqlite.OpenManagement(t.Context(), filepath.Join(directory, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identity.Close() })
	binary := filepath.Join(t.TempDir(), "yuhaiin-linux-amd64")
	if err := os.WriteFile(binary, []byte("prospective executable; never executed"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := Describe(t.Context(), binary, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	return directory, m
}

func TestManifestUsesObservedOwnersAndRejectsUnsafeSchemaTransitions(t *testing.T) {
	for _, fault := range []string{"same", "forward", "downgrade", "changed_name", "changed_statement", "changed_transform", "missing_state", "missing_identity", "alias"} {
		t.Run(fault, func(t *testing.T) {
			directory, m := fixture(t)
			catalog := m.Schemas["configuration"]
			switch fault {
			case "forward":
				m.Schemas["configuration"] = append(catalog, sqlite.MigrationDescriptor{Version: catalog[len(catalog)-1].Version + 1, Name: "future_migration", SHA256: strings.Repeat("a", 64)})
			case "downgrade":
				m.Schemas["configuration"] = catalog[:len(catalog)-1]
			case "changed_name":
				catalog[0].Name = "foreign"
			case "changed_statement":
				catalog[0].SHA256 = strings.Repeat("a", 64)
			case "changed_transform":
				catalog[0].Transform = !catalog[0].Transform
			case "missing_state":
				if err := os.Remove(filepath.Join(directory, "state.db")); err != nil {
					t.Fatal(err)
				}
			case "missing_identity":
				if err := os.Remove(filepath.Join(directory, "management.db")); err != nil {
					t.Fatal(err)
				}
			case "alias":
				path := filepath.Join(directory, "state.db")
				if err := os.Rename(path, path+".other"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".other", path); err != nil {
					t.Fatal(err)
				}
			}
			status, err := m.Check(t.Context(), directory)
			switch fault {
			case "same", "missing_identity":
				if err != nil || status.State != "compatible" || status.DatabaseRecoveryRequired {
					t.Fatal(status, err)
				}
			case "forward":
				if err != nil || status.State != "migration_required" || !status.DatabaseRecoveryRequired {
					t.Fatal(status, err)
				}
			default:
				if status.State != "incompatible" {
					t.Fatal("unsafe transition accepted", status, err)
				}
			}
		})
	}
}
func TestManifestRejectsCorruptionUnknownFieldsAndOversize(t *testing.T) {
	_, m := fixture(t)
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{data[:len(data)-1], append([]byte(`{"unexpected":true,`), data[1:]...), append([]byte(`{"version":1,`), data[1:]...), bytes.Repeat([]byte(" "), MaxManifestBytes+1)} {
		if _, err := Parse(bad); err == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
	m.Schemas["configuration"][0].Version = -1
	if err := m.Validate(); err == nil {
		t.Fatal("invalid migration descriptor accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Describe(ctx, "unopened", "linux", "amd64"); err == nil {
		t.Fatal("cancelled metadata operation succeeded")
	}
}
