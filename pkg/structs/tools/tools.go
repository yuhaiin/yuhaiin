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
	Url        string `json:"url"`
	License    string `json:"license"`
	LicenseUrl string `json:"license_url"`
}

type Log struct {
	Log string `json:"log"`
}

type Logv2 struct {
	Log []string `json:"log"`
}
