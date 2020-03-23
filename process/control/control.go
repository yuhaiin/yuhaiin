package ServerControl

import (
	"errors"
	"github.com/Asutorufa/SsrMicroClient/config"
	"github.com/Asutorufa/SsrMicroClient/net/proxy/shadowsocks/client"
	socks5client "github.com/Asutorufa/SsrMicroClient/net/proxy/socks5/client"
	"github.com/Asutorufa/SsrMicroClient/subscr"
	"log"
	"net"
	"os/exec"
)

type Control struct {
	Match    *OutboundMatch
	OutBound *OutBound
	ssrCmd   *exec.Cmd
}

func NewControl() (*Control, error) {
	x := &Control{}
	var err error
	x.Match, err = NewOutboundMatch(nil)
	if err != nil {
		return nil, err
	}
	if err := x.ChangeNode(); err != nil {
		return nil, err
	}
	if x.OutBound, err = NewOutBound(); err != nil {
		return nil, err
	}
	x.OutBound.changeForwardConn(x.Match.Forward)
	x.Start()
	return x, nil
}

func (c *Control) ReSet() error {
	if c.ssrCmd != nil {
		if err := c.ssrCmd.Process.Kill(); err != nil {
			return err
		}
		c.ssrCmd = nil
	}
	return nil
}

func (c *Control) ChangeNode() error {
	if err := c.ReSet(); err != nil {
		return err
	}
	nNode, err := subscr.GetNowNode()
	if err != nil {
		return err
	}
	switch nNode.(type) {
	case *subscr.Shadowsocks:
		conn, err := client.NewShadowosocks(
			nNode.(*subscr.Shadowsocks).Method,
			nNode.(*subscr.Shadowsocks).Password,
			net.JoinHostPort(nNode.(*subscr.Shadowsocks).Server, nNode.(*subscr.Shadowsocks).Port),
			nNode.(*subscr.Shadowsocks).Plugin,
			nNode.(*subscr.Shadowsocks).PluginOpt)
		if err != nil {
			return err
		}
		c.Match.ChangeForward(conn.Conn)
	case *subscr.Shadowsocksr:
		c.ssrCmd, err = ShadowsocksrCmd(nNode.(*subscr.Shadowsocksr))
		if err != nil {
			return err
		}
		go func() {
			if err := c.ssrCmd.Run(); err != nil {
				log.Println(err)
			}
		}()
		conFig, err := config.SettingDecodeJSON()
		if err != nil {
			return err
		}
		c.Match.ChangeForward(func(host string) (conn net.Conn, err error) {
			cli := socks5client.Client{Address: host, Server: conFig.LocalAddress, Port: conFig.LocalPort}
			return cli.NewSocks5Client()
		})
	default:
		return errors.New("no support type proxy")
	}
	return nil
}

func (c *Control) Start() {
	c.OutBound.Start()
}
