package backup

import (
	"github.com/Asutorufa/yuhaiin/pkg/config"
	"github.com/Asutorufa/yuhaiin/pkg/protocol"
)

type Nodes struct {
	Nodes map[string]*protocol.Point `json:"nodes,omitempty"`
}

type Subscribes struct {
	Links map[string]*protocol.Link `json:"links,omitempty"`
}

type Rules struct {
	Config *config.ConfigV2        `json:"config,omitempty"`
	Rules  []*config.RuleV2        `json:"rules,omitempty"`
	Lists  map[string]*config.List `json:"lists,omitempty"`
}

type Tags struct {
	Tags map[string]*protocol.Tags `json:"tags,omitempty"`
}

type BackupContent struct {
	Nodes      *Nodes                `json:"nodes,omitempty"`
	Subscribes *Subscribes           `json:"subscribes,omitempty"`
	Dns        *config.DnsConfigV2   `json:"dns,omitempty"`
	Inbounds   *config.InboundConfig `json:"inbounds,omitempty"`
	Rules      *Rules                `json:"rules,omitempty"`
	Tags       *Tags                 `json:"tag,omitempty"`
}

type RestoreSource int32

const (
	RestoreSourceUnknown RestoreSource = 0
	RestoreSourceS3      RestoreSource = 1
)

type RestoreOption struct {
	All        bool          `json:"all,omitempty"`
	Rules      bool          `json:"rules,omitempty"`
	Lists      bool          `json:"lists,omitempty"`
	Nodes      bool          `json:"nodes,omitempty"`
	Tags       bool          `json:"tags,omitempty"`
	Dns        bool          `json:"dns,omitempty"`
	Inbounds   bool          `json:"inbounds,omitempty"`
	Subscribes bool          `json:"subscribes,omitempty"`
	Source     RestoreSource `json:"source,omitempty"`
}
