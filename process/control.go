package process

import (
	"errors"
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/proxy/shadowsocks/client"
	"github.com/Asutorufa/yuhaiin/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/subscr"
	"log"
	"net"
	"os/exec"
)

var (
	ssrCmd *exec.Cmd
)

func controlInit() {
	if err := ChangeNode(); err != nil {
		log.Print(err)
		return
	}
}

func ReSet() error {
	if ssrCmd != nil && ssrCmd.Process != nil {
		if err := ssrCmd.Process.Kill(); err != nil {
			return err
		}
		ssrCmd = nil
	}
	return nil
}

func ChangeNode() error {
	if err := ReSet(); err != nil {
		return err
	}
	nNode, err := subscr.GetNowNode()
	if err != nil {
		return err
	}
	switch nNode.(type) {
	case *subscr.Shadowsocks:
		conn, err := client.NewShadowsocks(
			nNode.(*subscr.Shadowsocks).Method,
			nNode.(*subscr.Shadowsocks).Password,
			net.JoinHostPort(nNode.(*subscr.Shadowsocks).Server, nNode.(*subscr.Shadowsocks).Port),
			nNode.(*subscr.Shadowsocks).Plugin,
			nNode.(*subscr.Shadowsocks).PluginOpt)
		if err != nil {
			return err
		}
		Conn = conn.Conn
	case *subscr.Shadowsocksr:
		ssrCmd, err = ShadowsocksrCmd(nNode.(*subscr.Shadowsocksr))
		if err != nil {
			return err
		}
		if err := ssrCmd.Start(); err != nil {
			return err
		}
		go func() {
			if err := ssrCmd.Wait(); err != nil {
				log.Println(err)
			}
		}()

		conFig, err := config.SettingDecodeJSON()
		if err != nil {
			return err
		}
		Conn = func(host string) (conn net.Conn, err error) {
			return socks5client.NewSocks5Client(conFig.LocalAddress, conFig.LocalPort, "", "", host)
		}
	default:
		return errors.New("no support type proxy")
	}
	return nil
}
