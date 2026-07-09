package api

type RuntimeInfo struct {
	Version   string   `json:"version"`
	Commit    string   `json:"commit"`
	BuildTime string   `json:"build_time"`
	GoVersion string   `json:"go_version"`
	Platform  string   `json:"platform"`
	Compiler  string   `json:"compiler"`
	Arch      string   `json:"arch"`
	OS        string   `json:"os"`
	Build     []string `json:"build"`
}
