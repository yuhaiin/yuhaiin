package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	buildversion "github.com/Asutorufa/yuhaiin/internal/version"
	"io"
	"net/http"
	"os"
	"runtime"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
)

// CompatibilityInspector is implemented by the installed host, which knows the
// actual data directory. The updater never guesses a global configuration path.
type CompatibilityInspector interface {
	InspectCompatibility(context.Context, compatibility.Manifest) (contract.CompatibilityStatus, error)
}

func (s *Service) inspectCompatibility(ctx context.Context, m compatibility.Manifest) (contract.CompatibilityStatus, error) {
	if m.Platform != s.targetOS || m.Architecture != s.targetArch {
		return contract.CompatibilityStatus{State: "incompatible", Reason: "target_platform_mismatch"}, nil
	}
	if host, ok := s.installer.(ProtectedInstaller); ok && m.UpdateGuard != 1 {
		if supported, _ := host.ProtectedUpdateSupported(); supported {
			return contract.CompatibilityStatus{State: "unknown", Reason: "target_update_receipt_unsupported"}, nil
		}
	}
	inspector, ok := s.installer.(CompatibilityInspector)
	if !ok {
		return contract.CompatibilityStatus{State: "unknown", Reason: "schema_inspection_unavailable"}, errors.New("installed host cannot inspect database compatibility")
	}
	return inspector.InspectCompatibility(ctx, m)
}

func (s *Service) releaseCompatibility(ctx context.Context, asset Asset) (compatibility.Manifest, error) {
	var empty compatibility.Manifest
	if asset.CompatibilityURL == "" {
		return empty, errors.New("release has no verified schema compatibility manifest; use reviewed offline recovery")
	}
	text, err := downloadText(ctx, s.client, asset.ChecksumURL)
	if err != nil {
		return empty, err
	}
	want, err := parseChecksum(text, asset.Name+compatibility.Suffix)
	if err != nil {
		return empty, errors.New("release compatibility manifest is absent from checksums")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.CompatibilityURL, nil)
	if err != nil {
		return empty, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return empty, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return empty, errors.New("release compatibility manifest is unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, compatibility.MaxManifestBytes+1))
	if err != nil || len(data) > compatibility.MaxManifestBytes {
		return empty, errors.New("release compatibility manifest exceeds its limit")
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != want {
		return empty, errors.New("release compatibility manifest checksum mismatch")
	}
	m, err := compatibility.Parse(data)
	if err != nil {
		return empty, err
	}
	binaryHash, err := parseChecksum(text, asset.Name)
	if err != nil {
		return empty, err
	}
	if m.Asset != asset.Name || m.SHA256 != binaryHash || m.Platform != s.targetOS || m.Architecture != s.targetArch || (asset.Size > 0 && m.Size != asset.Size) {
		return empty, errors.New("release compatibility manifest does not describe the selected binary")
	}
	return m, nil
}

func writeStagedCompatibility(path string, m compatibility.Manifest) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path+compatibility.Suffix, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

// InspectStagedCompatibility independently rechecks privileged-helper input.
// A staged binary is never executed to discover its schema capabilities.
func InspectStagedCompatibility(ctx context.Context, path, dataDir string) (compatibility.Manifest, contract.CompatibilityStatus, error) {
	var empty compatibility.Manifest
	var status contract.CompatibilityStatus
	m, err := readCompatibilityFile(path + compatibility.Suffix)
	if err != nil {
		return empty, status, errors.New("staged compatibility manifest is unavailable or invalid")
	}
	architecture := buildversion.ReleaseArch
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	if m.Platform != runtime.GOOS || m.Architecture != architecture {
		return empty, status, errors.New("staged executable targets a different platform or CPU level")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != m.Size {
		return empty, status, errors.New("invalid staged executable type or size")
	}
	if err := m.VerifyPlatform(path); err != nil {
		return empty, status, err
	}
	observed, err := compatibility.Describe(ctx, path, m.Platform, m.Architecture)
	if err != nil || observed.SHA256 != m.SHA256 || observed.Size != m.Size {
		return empty, status, errors.New("staged executable differs from its compatibility manifest")
	}
	status, err = m.Check(ctx, dataDir)
	if err == nil && status.State != "compatible" {
		err = errors.New("database migration or incompatible binary requires a coordinated recovery point; use offline recovery until an update recovery point is prepared")
	}
	return m, status, err
}
