package node

type TagType int32

const (
	TagTypeNode   TagType = 0
	TagTypeMirror TagType = 1
)

type Tags struct {
	Tag  string   `json:"tag"`
	Type TagType  `json:"type"`
	Hash []string `json:"hash"`
}
