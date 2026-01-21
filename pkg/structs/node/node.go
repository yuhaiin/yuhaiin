package node

type Node struct {
	Tcp       *Point          `json:"tcp"`
	Udp       *Point          `json:"udp"`
	Links     map[string]Link `json:"links"`
	Manager   *Manager        `json:"manager"`
}

type Manager struct {
	Nodes     map[string]Point   `json:"nodes"`
	Tags      map[string]Tags    `json:"tags"`
	Publishes map[string]Publish `json:"publishes"`
}
