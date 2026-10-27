package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
)

type rejectingInspector struct {
	testInstaller
	state string
}

func TestHistoryCompatibilityRejectsForeignPlatformBeforeSchemaInspection(t *testing.T) {
	service := NewService(Options{Installer: &rejectingInspector{state: "compatible"}, TargetOS: "linux", TargetArch: "amd64"})
	status, err := service.inspectCompatibility(t.Context(), compatibility.Manifest{Platform: "windows", Architecture: "amd64"})
	if err != nil || status.State != "incompatible" || status.Reason != "target_platform_mismatch" {
		t.Fatal("foreign-platform history was advertised as compatible", status, err)
	}
}

func (i *rejectingInspector) InspectCompatibility(context.Context, compatibility.Manifest) (contract.CompatibilityStatus, error) {
	return contract.CompatibilityStatus{State: i.state}, nil
}

func TestReleaseCompatibilityRejectsUnverifiedMetadataBeforeDownloadingBinary(t *testing.T) {
	for _, fault := range []string{"missing", "checksum", "digest", "platform", "oversized", "migration", "incompatible", "changed"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			binary := filepath.Join(directory, "yuhaiin-linux-amd64")
			if err := os.WriteFile(binary, []byte("never executed"), 0600); err != nil {
				t.Fatal(err)
			}
			manifest, err := compatibility.Describe(t.Context(), binary, "linux", "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if fault == "digest" {
				manifest.SHA256 = strings.Repeat("0", 64)
			}
			if fault == "platform" {
				manifest.Platform = "darwin"
			}
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			binaryHash, _ := fileSHA256(binary)
			checksums := binaryHash + "  yuhaiin-linux-amd64\n" + hex.EncodeToString(sum[:]) + "  yuhaiin-linux-amd64.update.json\n"
			if fault == "checksum" {
				raw = append(raw, ' ')
			}
			if fault == "oversized" {
				raw = []byte(strings.Repeat(" ", compatibility.MaxManifestBytes+1))
			}
			var binaryRequests atomic.Int32
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body := ""
				switch r.URL.Path {
				case "/releases":
					assets := []releaseAsset{{Name: manifest.Asset, URL: "https://test/binary", Size: manifest.Size}, {Name: "checksums.txt", URL: "https://test/checksums"}}
					if fault != "missing" {
						assets = append(assets, releaseAsset{Name: manifest.Asset + compatibility.Suffix, URL: "https://test/manifest"})
					}
					data, _ := json.Marshal([]release{{Tag: "v2.0.0", Assets: assets}})
					body = string(data)
				case "/checksums":
					body = checksums
				case "/manifest":
					body = string(raw)
				case "/binary":
					binaryRequests.Add(1)
					body = "never executed"
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})
			inspector := &rejectingInspector{dir: directory, state: "compatible"}
			if fault == "migration" {
				inspector.state = "migration_required"
			}
			if fault == "incompatible" {
				inspector.state = "incompatible"
			}
			service := NewService(Options{HTTPClient: &http.Client{Transport: transport}, Installer: inspector, ReleasesURL: "https://test/releases", CurrentVersion: "v1.0.0", TargetOS: "linux", TargetArch: "amd64"})
			result, err := service.Check(t.Context(), "stable")
			if err != nil || !result.UpdateAvailable || result.Compatibility == nil {
				t.Fatal("release should remain inspectable", err, result)
			}
			if fault == "changed" {
				inspector.state = "incompatible"
			} else if result.Compatibility.State == "compatible" {
				t.Fatal("unsafe metadata or schema advertised as compatible", fault)
			}
			if err := service.Apply(t.Context(), contract.ApplyRequest{TargetTag: "v2.0.0"}); err == nil {
				t.Fatal("unsafe target admitted")
			}
			if binaryRequests.Load() != 0 || inspector.started != "" {
				t.Fatal("unsafe target reached download/installer")
			}
		})
	}
}
