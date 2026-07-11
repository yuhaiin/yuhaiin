package update

import "time"

const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
	ChannelMain   = "main"
)

type CheckResult struct {
	Supported       bool      `json:"supported"`
	Channel         string    `json:"channel"`
	CurrentVersion  string    `json:"currentVersion"`
	TargetVersion   string    `json:"targetVersion"`
	TargetTag       string    `json:"targetTag"`
	Prerelease      bool      `json:"prerelease"`
	ReleaseURL      string    `json:"releaseUrl"`
	ReleaseNotes    string    `json:"releaseNotes"`
	PublishedAt     time.Time `json:"publishedAt"`
	AssetName       string    `json:"assetName"`
	AssetSHA256     string    `json:"assetSha256"`
	UpdateAvailable bool      `json:"updateAvailable"`
	Reason          string    `json:"reason"`
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
