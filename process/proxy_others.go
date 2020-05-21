// +build !windows

package process

import (
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/redirserver"
	"log"
	"net/url"
)

func extendsProxyInit(conFig *config.Setting) {
	if conFig.RedirProxyAddress != "" {
		redirAddr, err := url.Parse("//" + conFig.RedirProxyAddress)
		if err != nil {
			log.Print(err)
			return
		}
		if Redir, err = redirserver.NewRedir(redirAddr.Hostname(), redirAddr.Port()); err != nil {
			log.Print(err)
			return
		}
	}
}

func extendsUpdateListen(conFig *config.Setting) error {
	if Redir.GetHost() != conFig.RedirProxyAddress {
		redirAddr, err := url.Parse("//" + conFig.RedirProxyAddress)
		if err != nil {
			return err
		}
		if Redir, err = redirserver.NewRedir(redirAddr.Hostname(), redirAddr.Port()); err != nil {
			return err
		}
	}
	return nil
}
