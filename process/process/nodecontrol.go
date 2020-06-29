package process

import (
	"errors"
	"log"
	"net"
	"os/exec"

	"github.com/Asutorufa/yuhaiin/process/controller"

	"github.com/Asutorufa/yuhaiin/net/proxy/shadowsocks/client"
	socks5client "github.com/Asutorufa/yuhaiin/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/subscr"
)

var (
	SsrCmd *exec.Cmd
)

func ReSet() error {
	if SsrCmd == nil || SsrCmd.Process == nil {
		return nil
	}
	if err := SsrCmd.Process.Kill(); err != nil {
		return err
	}
	SsrCmd = nil
	return nil
}

func ChangeNode() error {
	if err := ReSet(); err != nil {
		return err
	}

	nNode, err := GetNowNode()
	if err != nil {
		return err
	}

	switch nNode.(type) {
	case *subscr.Shadowsocks:
		// ip, err := getIP(nNode.(*subscr.Shadowsocks).Server)
		// if err == nil {
		// 	nNode.(*subscr.Shadowsocks).Server = ip.String()
		// }
		conn, err := client.NewShadowsocks(
			nNode.(*subscr.Shadowsocks).Method,
			nNode.(*subscr.Shadowsocks).Password,
			net.JoinHostPort(nNode.(*subscr.Shadowsocks).Server, nNode.(*subscr.Shadowsocks).Port),
			nNode.(*subscr.Shadowsocks).Plugin,
			nNode.(*subscr.Shadowsocks).PluginOpt)
		if err != nil {
			return err
		}
		MatchCon.SetProxy(conn.Conn)
	case *subscr.Shadowsocksr:
		var localHost string
		SsrCmd, localHost, err = controller.ShadowsocksrCmd(nNode.(*subscr.Shadowsocksr))
		if err != nil {
			return err
		}
		if err := SsrCmd.Start(); err != nil {
			return err
		}
		go func() {
			if err := SsrCmd.Wait(); err != nil {
				log.Println(err)
			}
		}()

		MatchCon.SetProxy(func(host string) (conn net.Conn, err error) {
			return socks5client.NewSocks5Client(localHost, "", "", host)
		})
	default:
		return errors.New("no support type proxy")
	}
	return nil
}
