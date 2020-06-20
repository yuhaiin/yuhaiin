// +build windows

package process

import (
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/redirserver"
)

var (
	Redir = &redirserver.Server{}
)

func extendsUpdateListen(conFig *config.Setting) error { return nil }
