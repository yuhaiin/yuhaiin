package node

type Origin int32

const (
	OriginReserve Origin = 0
	OriginRemote  Origin = 101
	OriginManual  Origin = 102
)

type Point struct {
	Hash      string     `json:"hash"`
	Name      string     `json:"name"`
	Group     string     `json:"group"`
	Origin    Origin     `json:"origin"`
	Protocols []Protocol `json:"protocols"`
}
