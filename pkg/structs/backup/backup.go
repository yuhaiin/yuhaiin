package backup

import (
	"github.com/Asutorufa/yuhaiin/pkg/structs/config"
	"github.com/Asutorufa/yuhaiin/pkg/structs/node"
)

type Nodes struct {
	Nodes map[string]node.Point `json:"nodes"`
}

type Subscribes struct {
	Links map[string]node.Link `json:"links"`
}

type Rules struct {
	Config config.Configv2          `json:"config"`
	Rules  []config.Rulev2          `json:"rules"`
	Lists  map[string]config.List `json:"lists"`
}

type Tags struct {
	Tags map[string]node.Tags `json:"tags"`
}

type BackupContent struct {
	Nodes      Nodes                `json:"nodes"`
	Subscribes Subscribes           `json:"subscribes"`
	Dns        config.DnsConfigV2   `json:"dns"`
	Inbounds   config.InboundConfig `json:"inbounds"`
	Rules      Rules                `json:"rules"`
	Tags       Tags                 `json:"tag"`
}

type RestoreSource int32

const (
	RestoreSourceUnknown RestoreSource = 0
	RestoreSourceS3      RestoreSource = 1
)

type RestoreOption struct {
	All        bool          `json:"all"`
	Rules      bool          `json:"rules"`
	Lists      bool          `json:"lists"`
	Nodes      bool          `json:"nodes"`
	Tags       bool          `json:"tags"`
	Dns        bool          `json:"dns"`
	Inbounds   bool          `json:"inbounds"`
	Subscribes bool          `json:"subscribes"`
	Source     RestoreSource `json:"source"`
}
