package ServerControl

import (
	"errors"
	"github.com/Asutorufa/SsrMicroClient/config"
	"github.com/Asutorufa/SsrMicroClient/net/proxy/shadowsocks/client"
	socks5client "github.com/Asutorufa/SsrMicroClient/net/proxy/socks5/client"
	"github.com/Asutorufa/SsrMicroClient/subscr"
	"log"
	"net"
)

type control struct {
	Match    *OutboundMatch
	OutBound *OutBound
}

func NewControl() (*control, error) {
	x := &control{}
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
	return x, nil
}

func (c *control) ChangeNode() error {
	nNode, err := subscr.GetNowNode2()
	if err != nil {
		return err
	}
	switch nNode.(type) {
	case subscr.Shadowsocks:
		conn, err := client.NewShadowosocks(
			nNode.(*subscr.Shadowsocks).Method,
			nNode.(*subscr.Shadowsocks).Password,
			nNode.(*subscr.Shadowsocks).Server,
			nNode.(*subscr.Shadowsocks).Plugin,
			nNode.(*subscr.Shadowsocks).PluginOpt)
		if err != nil {
			return err
		}
		c.Match.ChangeForward(conn.Conn)
		return nil
	case subscr.Shadowsocksr:
		cmd, err := ShadowsocksrCmd(nNode.(*subscr.Shadowsocksr))
		if err != nil {
			return err
		}
		go func() {
			if err := cmd.Run(); err != nil {
				log.Println(err)
			}
		}()
		conFig, err := config.SettingDecodeJSON2()
		if err != nil {
			return err
		}
		c.Match.ChangeForward(func(host string) (conn net.Conn, err error) {
			return socks5client.Client{Address: host, Server: conFig.LocalPort, Port: conFig.LocalPort}.NewSocks5Client()
		})
		return nil
	default:
		return errors.New("no support type proxy")
	}
}

func (c *control) Start() {
	c.OutBound.Start()
}
