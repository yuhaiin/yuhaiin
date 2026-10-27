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
}

type CheckRequest struct {
	Channel           string `json:"channel"`
	IncludePrerelease bool   `json:"includePrerelease"`
}

type ApplyRequest struct {
	Channel           string `json:"channel"`
	TargetTag         string `json:"targetTag"`
	IncludePrerelease bool   `json:"includePrerelease"`
}

type Status struct {
	Running         bool   `json:"running"`
	Stage           string `json:"stage"`
	Progress        int    `json:"progress"`
	BytesDownloaded int64  `json:"bytesDownloaded"`
	TotalBytes      int64  `json:"totalBytes"`
	Error           string `json:"error"`
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
	Items []HistoryEntry `json:"items"`
}

type RollbackRequest struct {
	ID string `json:"id"`
}
