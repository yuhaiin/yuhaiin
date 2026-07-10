package tools

type Interfaces struct {
	Interfaces []Interface `json:"interfaces"`
}

type Interface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

type Licenses struct {
	Yuhaiin []License `json:"yuhaiin"`
	Android []License `json:"android"`
}

type License struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	License    string `json:"license"`
	LicenseURL string `json:"licenseUrl"`
}

type LogBatch struct {
	Log []string `json:"log"`
}
