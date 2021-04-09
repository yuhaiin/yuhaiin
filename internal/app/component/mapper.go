package component

type MODE int
type RespType int

const (
	OTHERS MODE = 0
	BLOCK  MODE = 1
	DIRECT MODE = 2
	// PROXY  MODE = 3

	IP     RespType = 0
	DOMAIN RespType = 1
)

var ModeMapping = map[MODE]string{
	OTHERS: "others(proxy)",
	DIRECT: "direct",
	BLOCK:  "block",
}

var Mode = map[string]MODE{
	"direct": DIRECT,
	// "proxy":  PROXY,
	"block": BLOCK,
}

type MapperResp struct {
	Mark MODE
	IP   RespType
}

type Mapper interface {
	Get(string) MapperResp
}
