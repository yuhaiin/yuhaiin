package process

import (
	"errors"
	"log"
	"net"
	"os/exec"

	"github.com/Asutorufa/yuhaiin/net/proxy/shadowsocks/client"
	socks5client "github.com/Asutorufa/yuhaiin/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/subscr"
)

var (
	ssrCmd *exec.Cmd
)

func ReSet() error {
	if ssrCmd == nil || ssrCmd.Process == nil {
		return nil
	}

	if err := ssrCmd.Process.Kill(); err != nil {
		return err
	}
	ssrCmd = nil
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
		ip, err := getIP(nNode.(*subscr.Shadowsocks).Server)
		if err == nil {
			nNode.(*subscr.Shadowsocks).Server = ip.String()
		}
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
		ssrCmd, localHost, err := ShadowsocksrCmd(nNode.(*subscr.Shadowsocksr))
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

		Conn = func(host string) (conn net.Conn, err error) {
			return socks5client.NewSocks5Client(localHost, "", "", host)
		}
	default:
		return errors.New("no support type proxy")
	}
	return nil
}
