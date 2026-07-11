package settings

type Settings struct {
	IPv6                bool            `json:"ipv6"`
	UseDefaultInterface bool            `json:"useDefaultInterface"`
	NetInterface        string          `json:"netInterface"`
	Pprof               bool            `json:"pprof"`
	SystemProxy         SystemProxy     `json:"systemProxy"`
	Logcat              Logcat          `json:"logcat"`
	Advanced            AdvancedConfig  `json:"advanced"`
	Backup              BackupReference `json:"backup"`
}

type SystemProxy struct {
	HTTP   bool `json:"http"`
	Socks5 bool `json:"socks5"`
}

type Logcat struct {
	Level              string `json:"level"`
	Save               bool   `json:"save"`
	IgnoreTimeoutError bool   `json:"ignoreTimeoutError"`
	IgnoreDNSError     bool   `json:"ignoreDnsError"`
}

type AdvancedConfig struct {
	UDPBufferSize          int32 `json:"udpBufferSize"`
	RelayBufferSize        int32 `json:"relayBufferSize"`
	UDPRingbufferSize      int32 `json:"udpRingbufferSize"`
	HappyEyeballsSemaphore int32 `json:"happyEyeballsSemaphore"`
}

type BackupReference struct {
	InstanceName   string `json:"instanceName"`
	Interval       uint64 `json:"interval"`
	LastBackupHash string `json:"lastBackupHash"`
}

type Info struct {
	Version   string   `json:"version"`
	Commit    string   `json:"commit"`
	BuildTime string   `json:"buildTime"`
	GoVersion string   `json:"goVersion"`
	Arch      string   `json:"arch"`
	Platform  string   `json:"platform"`
	OS        string   `json:"os"`
	Compiler  string   `json:"compiler"`
	Build     []string `json:"build"`
}
