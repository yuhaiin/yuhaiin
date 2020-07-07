// +build !windows

package controller

import (
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/redirserver"
)

func (l *LocalListen) SetRedirHost(host string) (err error) {
	if l.Redir == nil {
		l.Redir, err = redirserver.NewRedir(host)
		return
	}
	return l.Redir.UpdateListen(host)
}
