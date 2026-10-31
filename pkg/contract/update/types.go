package update

import "time"

const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
	ChannelMain   = "main"
)

// CompatibilityStatus describes observed schemas, not reversible migrations.
type CompatibilityStatus struct {
	State                    string `json:"state"`
	Reason                   string `json:"reason"`
	CurrentConfiguration     int    `json:"currentConfiguration"`
	CurrentManagement        int    `json:"currentManagement"`
	TargetConfiguration      int    `json:"targetConfiguration"`
	TargetManagement         int    `json:"targetManagement"`
	DatabaseRecoveryRequired bool   `json:"databaseRecoveryRequired"`
}

type RecoveryReadiness struct {
	Enabled   bool   `json:"enabled"`
	Supported bool   `json:"supported"`
	Ready     bool   `json:"ready"`
	Reason    string `json:"reason"`
}

type OperationStatus struct {
	ID           string    `json:"id"`
	Phase        string    `json:"phase"`
	BackupJobID  string    `json:"backupJobId,omitempty"`
	BackupID     string    `json:"backupId,omitempty"`
	TargetSHA256 string    `json:"targetSha256"`
	SourceSHA256 string    `json:"sourceSha256"`
	ErrorCode    string    `json:"errorCode,omitempty"`
	StartedAt    time.Time `json:"startedAt"`
	CompletedAt  time.Time `json:"completedAt,omitzero"`
}

type CheckResult struct {
	Supported       bool                 `json:"supported"`
	Channel         string               `json:"channel"`
	CurrentVersion  string               `json:"currentVersion"`
	TargetVersion   string               `json:"targetVersion"`
	TargetTag       string               `json:"targetTag"`
	Prerelease      bool                 `json:"prerelease"`
	ReleaseURL      string               `json:"releaseUrl"`
	ReleaseNotes    string               `json:"releaseNotes"`
	PublishedAt     time.Time            `json:"publishedAt"`
	AssetName       string               `json:"assetName"`
	AssetSHA256     string               `json:"assetSha256"`
	UpdateAvailable bool                 `json:"updateAvailable"`
	Reason          string               `json:"reason"`
	Compatibility   *CompatibilityStatus `json:"compatibility,omitempty"`
	Recovery        *RecoveryReadiness   `json:"recovery,omitempty"`
}

type CheckRequest struct {
	Channel           string `json:"channel"`
	IncludePrerelease bool   `json:"includePrerelease"`
}

type ApplyRequest struct {
	OperationID            string `json:"operationId,omitempty"`
	Channel                string `json:"channel"`
	TargetTag              string `json:"targetTag"`
	IncludePrerelease      bool   `json:"includePrerelease"`
	ExpectedSHA256         string `json:"expectedSha256,omitempty"`
	ConfirmMaintenance     bool   `json:"confirmMaintenance"`
	ConfirmManualRecovery  bool   `json:"confirmManualRecovery"`
	ConfirmNoRecoveryPoint bool   `json:"confirmNoRecoveryPoint"`
}

type Status struct {
	Running         bool             `json:"running"`
	Stage           string           `json:"stage"`
	Progress        int              `json:"progress"`
	BytesDownloaded int64            `json:"bytesDownloaded"`
	TotalBytes      int64            `json:"totalBytes"`
	Error           string           `json:"error"`
	Operation       *OperationStatus `json:"operation,omitempty"`
}

type HistoryEntry struct {
	ID            string               `json:"id"`
	Version       string               `json:"version"`
	Commit        string               `json:"commit"`
	Size          int64                `json:"size"`
	SavedAt       time.Time            `json:"savedAt"`
	Compatibility *CompatibilityStatus `json:"compatibility,omitempty"`
}

type HistoryResult struct {
	Items    []HistoryEntry     `json:"items"`
	Recovery *RecoveryReadiness `json:"recovery,omitempty"`
}

type RollbackRequest struct {
	OperationID            string `json:"operationId,omitempty"`
	ID                     string `json:"id"`
	ConfirmMaintenance     bool   `json:"confirmMaintenance"`
	ConfirmManualRecovery  bool   `json:"confirmManualRecovery"`
	ConfirmNoRecoveryPoint bool   `json:"confirmNoRecoveryPoint"`
}
