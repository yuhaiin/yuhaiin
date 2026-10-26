package backup

import "time"

// RecoveryManifest is authenticated inside the encrypted archive. It contains
// inventory and build metadata only; keys and credential contents are file data.
type RecoveryManifest struct {
	Format          string         `json:"format"`
	Version         int            `json:"version"`
	ID              string         `json:"id"`
	InstanceID      string         `json:"instanceId"`
	CreatedAt       time.Time      `json:"createdAt"`
	Consistency     string         `json:"consistency"`
	IncludesHistory bool           `json:"includesHistory"`
	Build           RecoveryBuild  `json:"build"`
	Files           []RecoveryFile `json:"files"`
}

type RecoveryBuild struct {
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	GoVersion    string `json:"goVersion"`
}

type RecoveryFile struct {
	Path          string `json:"path"`
	Role          string `json:"role"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
	SchemaVersion int    `json:"schemaVersion,omitzero"`
}
