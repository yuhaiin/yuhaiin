package dns

import (
	"github.com/Asutorufa/yuhaiin/net/common"
	"time"
)

var (
	cache = common.NewCacheExtend(time.Minute * 10)
)
