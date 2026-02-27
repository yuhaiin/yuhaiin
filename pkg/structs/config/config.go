package config

type S3 struct {
	Enabled      bool   `json:"enabled"`
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	Bucket       string `json:"bucket"`
	Region       string `json:"region"`
	EndpointUrl  string `json:"endpoint_url"`
	UsePathStyle bool   `json:"use_path_style"`
	StorageClass string `json:"storage_class"`
}

type BackupOption struct {
	InstanceName   string `json:"instance_name"`
	S3             *S3    `json:"s3"`
	Interval       uint64 `json:"interval"`
	LastBackupHash string `json:"last_backup_hash"`
}

type Setting struct {
	Ipv6                bool            `json:"ipv6"`
	UseDefaultInterface bool            `json:"use_default_interface"`
	NetInterface        string          `json:"net_interface"`
	SystemProxy         *SystemProxy     `json:"system_proxy"`
	Bypass              *BypassConfig    `json:"bypass"`
	Dns                 *DnsConfig      `json:"dns"`
	Server              *InboundConfig   `json:"server"`
	Logcat              *Logcat         `json:"logcat"`
	ConfigVersion       *ConfigVersion   `json:"config_version"`
	Platform            *Platform       `json:"platform"`
	AdvancedConfig      *AdvancedConfig `json:"advanced_config"`
	Backup              *BackupOption    `json:"backup"`
}

type AdvancedConfig struct {
	UdpBufferSize           int32 `json:"udp_buffer_size"`
	RelayBufferSize         int32 `json:"relay_buffer_size"`
	UdpRingbufferSize       int32 `json:"udp_ringbuffer_size"`
	HappyeyeballsSemaphore int32 `json:"happyeyeballs_semaphore"`
}

type SystemProxy struct {
	Http   bool `json:"http"`
	Socks5 bool `json:"socks5"`
}

type Info struct {
	Version   string   `json:"version"`
	Commit    string   `json:"commit"`
	BuildTime string   `json:"build_time"`
	GoVersion string   `json:"go_version"`
	Arch      string   `json:"arch"`
	Platform  string   `json:"platform"`
	Os        string   `json:"os"`
	Compiler  string   `json:"compiler"`
	Build     []string `json:"build"`
}

type ConfigVersion struct {
	Version uint64 `json:"version"`
}

type Platform struct {
	AndroidApp bool `json:"android_app"`
}
