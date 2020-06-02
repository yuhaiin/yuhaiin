// +build !windows

package process

import (
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/redirserver"
)

func extendsProxyInit(conFig *config.Setting) {
	Redir, _ = redirserver.NewRedir(conFig.RedirProxyAddress)
}

func extendsUpdateListen(conFig *config.Setting) error {
	return Redir.UpdateListen(conFig.RedirProxyAddress)
}
