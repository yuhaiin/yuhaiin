package dns

import (
	"time"

	"github.com/Asutorufa/yuhaiin/net/common"
)

var (
	cache = common.NewCacheExtend(time.Minute * 10)
)
