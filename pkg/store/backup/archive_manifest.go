package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"
	"unicode/utf8"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
)

func ValidateRecoveryManifest(manifest contract.RecoveryManifest) error {
	if manifest.Format != RecoveryFormat || (manifest.Version != 1 && manifest.Version != RecoveryVersion) {
		return errors.New("unsupported recovery format or version")
	}
	for _, id := range []string{manifest.ID, manifest.InstanceID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id || parsed == (uuid.UUID{}) {
			return errors.New("invalid recovery or instance identifier")
		}
	}
	if manifest.CreatedAt.IsZero() || manifest.Consistency != "offline-maintenance" {
		return errors.New("missing creation time or coordinated maintenance guarantee")
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > MaxRecoveryFiles {
		return errors.New("invalid recovery file count")
	}
	if manifest.Build.Version == "" || manifest.Build.Platform == "" || manifest.Build.Architecture == "" || manifest.Build.GoVersion == "" {
		return errors.New("missing recovery build metadata")
	}
	if len(manifest.Build.Version) > 256 || len(manifest.Build.Commit) > 256 || len(manifest.Build.GoVersion) > 256 || len(manifest.Build.Platform) > 64 || len(manifest.Build.Architecture) > 64 {
		return errors.New("invalid recovery build metadata")
	}
	if manifest.Version == 1 && (manifest.CompleteInventory || manifest.SourceDirectory != "" || manifest.Runtime != nil || len(manifest.Requirements) != 0) {
		return errors.New("legacy recovery manifest contains unsupported extensions")
	}
	if manifest.SourceDirectory != "" && !recoverySourcePath(manifest.SourceDirectory) {
		return errors.New("invalid recovery source directory")
	}
	if manifest.CompleteInventory && (manifest.SourceDirectory == "" || manifest.Runtime == nil) {
		return errors.New("complete inventory lacks startup inputs")
	}
	if manifest.Runtime != nil {
		if err := ValidateRecoveryRuntime(*manifest.Runtime); err != nil {
			return err
		}
	}
	if len(manifest.Requirements) > MaxRecoveryFiles {
		return errors.New("too many recovery requirements")
	}
	for _, requirement := range manifest.Requirements {
		if requirement.Kind != "identity_not_initialized" || len(requirement.NodeID) > 256 || len(requirement.Path) > 4096 {
			return errors.New("invalid recovery requirement")
		}
	}
	names := make(map[string]struct{}, len(manifest.Files))
	var total int64
	configuration := false
	for _, file := range manifest.Files {
		if err := validateRecoveryPath(file.Path); err != nil {
			return err
		}
		if file.Size < 0 || file.Size > MaxRecoveryDataBytes-total {
			return errors.New("recovery data exceeds 100 GiB")
		}
		total += file.Size
		digest, err := hex.DecodeString(file.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return errors.New("invalid recovery content digest")
		}
		if file.SchemaVersion < 0 || file.SchemaVersion > 1_000_000 {
			return errors.New("invalid recovery database schema")
		}
		switch file.Role {
		case "configuration_database":
			if file.Path != "state.db" || file.SchemaVersion < 1 {
				return errors.New("invalid configuration database inventory")
			}
			configuration = true
		case "management_database":
			if file.Path != "management.db" || file.SchemaVersion < 1 {
				return errors.New("invalid management database inventory")
			}
		case "listener_certificate", "protocol_identity", "dependency":
		default:
			return errors.New("unknown recovery file role")
		}
		if file.SourcePath != "" && (manifest.Version == 1 || !recoverySourcePath(file.SourcePath) || (file.Role != "dependency" && file.Role != "listener_certificate")) {
			return errors.New("invalid external recovery dependency")
		}
		name := strings.ToLower(file.Path)
		if slices.Contains([]string{"state.db-wal", "state.db-shm", "state.db-journal", "management.db-wal", "management.db-shm", "management.db-journal"}, name) {
			return errors.New("live SQLite sidecars cannot be restored from an archive")
		}
		if _, exists := names[name]; exists {
			return errors.New("duplicate recovery paths")
		}
		names[name] = struct{}{}
	}
	if !configuration {
		return errors.New("recovery archive is missing the configuration database")
	}
	if manifest.CompleteInventory && manifest.Runtime.ManagementAuth {
		if _, exists := names["management.db"]; !exists {
			return errors.New("recovery archive omits the enabled management identity database")
		}
	}
	for name := range names {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if _, exists := names[parent]; exists {
				return errors.New("conflicting recovery paths")
			}
		}
	}
	return nil
}

func validateRecoveryPath(name string) error {
	if len(name) > 1024 || !utf8.ValidString(name) || !fs.ValidPath(name) || name == "." || path.Clean(name) != name || strings.ContainsAny(name, "\\:\x00<>\"|?*") {
		return errors.New("invalid recovery file path")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return errors.New("control character in recovery path")
		}
	}
	// Portable names prevent Windows device/ADS aliases and cross-platform
	// collisions. Extraction also uses exclusive creation under an os.Root.
	for part := range strings.SplitSeq(name, "/") {
		if strings.TrimRight(part, ". ") != part {
			return errors.New("invalid portable recovery path")
		}
		base, _, _ := strings.Cut(strings.ToUpper(part), ".")
		if slices.Contains([]string{"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}, base) {
			return errors.New("reserved recovery path")
		}
	}
	first, _, _ := strings.Cut(strings.ToLower(name), "/")
	if first == ".configuration.lock" || first == "lock" || strings.HasPrefix(first, ".recovery-") {
		return errors.New("recovery path conflicts with lifecycle storage")
	}
	return nil
}

// ValidateRecoveryDestination applies the archive's portable, confined path
// rules to a configuration-rebound restore destination.
func ValidateRecoveryDestination(name string) error { return validateRecoveryPath(name) }

func recoverySourcePath(value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return strings.HasPrefix(value, "/") || strings.HasPrefix(value, "\\\\") || (len(value) > 2 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && (value[2] == '/' || value[2] == '\\'))
}

func ValidateRecoveryRuntime(inputs contract.RecoveryRuntime) error {
	if !recoverySourcePath(inputs.WorkingDirectory) {
		return errors.New("invalid recovery working directory")
	}
	switch inputs.ManagementTLS {
	case "disabled", "self_signed":
		if inputs.CertificateFile != "" || inputs.KeyFile != "" {
			return errors.New("unexpected management TLS file pair")
		}
	case "files":
		if inputs.CertificateFile == "" || inputs.KeyFile == "" {
			return errors.New("missing management TLS file pair")
		}
	default:
		return errors.New("unsupported management TLS recovery mode")
	}
	for _, value := range []string{inputs.CertificateFile, inputs.KeyFile, inputs.ExternalWebDirectory, inputs.ListenAddress} {
		if len(value) > 4096 || !utf8.ValidString(value) {
			return errors.New("invalid recovery startup input")
		}
		for _, r := range value {
			if r < 0x20 || r == 0x7f {
				return errors.New("control character in recovery startup input")
			}
		}
	}
	return nil
}
