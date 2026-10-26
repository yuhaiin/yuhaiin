package backup

import "time"

const MaxRecoveryDataBytes = int64(100 << 30)

// RecoveryManifest is authenticated inside the encrypted archive. It contains
// inventory and build metadata only; keys and credential contents are file data.
type RecoveryManifest struct {
	Format            string                `json:"format"`
	Version           int                   `json:"version"`
	ID                string                `json:"id"`
	InstanceID        string                `json:"instanceId"`
	CreatedAt         time.Time             `json:"createdAt"`
	Consistency       string                `json:"consistency"`
	IncludesHistory   bool                  `json:"includesHistory"`
	Build             RecoveryBuild         `json:"build"`
	Files             []RecoveryFile        `json:"files"`
	CompleteInventory bool                  `json:"completeInventory,omitzero"`
	SourceDirectory   string                `json:"sourceDirectory,omitempty"`
	Runtime           *RecoveryRuntime      `json:"runtime,omitzero"`
	Requirements      []RecoveryRequirement `json:"requirements,omitempty"`
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
	SourcePath    string `json:"sourcePath,omitempty"`
}

// RecoveryRuntime records startup inputs for backup inventory, not a second
// authoritative TLS configuration. It never contains certificate/key contents.
type RecoveryRuntime struct {
	ManagementAuth       bool   `json:"managementAuth,omitzero"`
	ManagementTLS        string `json:"managementTLS"`
	CertificateFile      string `json:"certificateFile,omitempty"`
	KeyFile              string `json:"keyFile,omitempty"`
	WorkingDirectory     string `json:"workingDirectory"`
	ListenAddress        string `json:"listenAddress,omitempty"`
	ExternalWebDirectory string `json:"externalWebDirectory,omitempty"`
}

type RecoveryRequirement struct {
	Kind   string `json:"kind"`
	NodeID string `json:"nodeId,omitempty"`
	Path   string `json:"path,omitempty"`
}
