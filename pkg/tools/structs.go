package tools

type Interfaces struct {
	Interfaces []*Interface `json:"interfaces,omitempty"`
}

type Interface struct {
	Name      string   `json:"name,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}

type Licenses struct {
	Yuhaiin []*License `json:"yuhaiin,omitempty"`
	Android []*License `json:"android,omitempty"`
}

type License struct {
	Name       string `json:"name,omitempty"`
	Url        string `json:"url,omitempty"`
	License    string `json:"license,omitempty"`
	LicenseUrl string `json:"license_url,omitempty"`
}

type Log struct {
	Log string `json:"log,omitempty"`
}

type Logv2 struct {
	Log []string `json:"log,omitempty"`
}
