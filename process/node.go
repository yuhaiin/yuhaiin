package process

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"

	"github.com/Asutorufa/yuhaiin/controller"
	"github.com/Asutorufa/yuhaiin/net/proxy/shadowsocks/client"
	socks5client "github.com/Asutorufa/yuhaiin/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/subscr"
)

func RefreshNodes() (err error) {
	Nodes, err = subscr.GetNodesJSON()
	return
}

func ChangeNNode(group string, node string) (erra error) {
	if Nodes.Node[group][node] == nil {
		return errors.New("not exist " + group + " - " + node)
	}
	Nodes.NowNode = Nodes.Node[group][node]

	err := subscr.SaveNode(Nodes)
	if err != nil {
		erra = fmt.Errorf("%v\nSaveNode() -> %v", erra, err)
	}

	err = ChangeNode()
	if err != nil {
		erra = fmt.Errorf("%v\nChangeNode -> %v", erra, err)
	}
	return
}

func GetNNodeAndNGroup() (node string, group string) {
	return Nodes.NowNode.(map[string]interface{})["name"].(string), Nodes.NowNode.(map[string]interface{})["group"].(string)
}

func GetNowNode() (interface{}, error) {
	return subscr.ParseNode(Nodes.NowNode.(map[string]interface{}))
}

func GetOneNode(group, nodeN string) (interface{}, error) {
	if Nodes.Node[group][nodeN] == nil {
		return nil, fmt.Errorf("GetOneNode:pa.Node[group][remarks] -> %v", errors.New("node is not exist"))
	}
	currentNode := Nodes.Node[group][nodeN].(map[string]interface{})

	node, err := subscr.ParseNode(currentNode)
	if err != nil {
		return nil, fmt.Errorf("GetOneNode:map2struct -> %v", err)
	}
	return node, nil
}

func GetNodes(group string) ([]string, error) {

	var nodeTmp []string
	for nodeRemarks := range Nodes.Node[group] {
		nodeTmp = append(nodeTmp, nodeRemarks)
	}
	sort.Strings(nodeTmp)
	return nodeTmp, nil
}

func GetGroups() ([]string, error) {
	var groupTmp []string
	for group := range Nodes.Node {
		groupTmp = append(groupTmp, group)
	}
	sort.Strings(groupTmp)
	return groupTmp, nil
}

func UpdateSub() error {
	err := subscr.GetLinkFromInt()
	if err != nil {
		return fmt.Errorf("UpdateSub() -> %v", err)
	}
	err = RefreshNodes()
	if err != nil {
		return fmt.Errorf("RefreshNodes() -> %v", err)
	}
	return nil
}

func GetLinks() ([]string, error) {
	var linkTmp []string
	for _, link := range Nodes.Link {
		linkTmp = append(linkTmp, link)
	}
	return linkTmp, nil
}

func AddLink(str string) error {
	Nodes.Link = append(Nodes.Link, str)
	return subscr.SaveNode(Nodes)
}

func DeleteLink(str string) error {
	for index := range Nodes.Link {
		if str == Nodes.Link[index] {
			Nodes.Link = append(Nodes.Link[:index], Nodes.Link[index+1:]...)
			break
		}
	}
	return subscr.SaveNode(Nodes)
}

var (
	SsrCmd     *exec.Cmd
	ssrRunning = false
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
	if ssrRunning {
		err := ReSet()
		if err != nil {
			return err
		}
	}

	nNode, err := GetNowNode()
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
		_ = MatchCon.SetAllOption(func(option *controller.OptionMatchCon) {
			option.Proxy = conn.Conn
		})
	case *subscr.Shadowsocksr:
		var localHost string
		SsrCmd, localHost, err = controller.ShadowsocksrCmd(nNode.(*subscr.Shadowsocksr), ConFig.SsrPath)
		if err != nil {
			return err
		}
		if err := SsrCmd.Start(); err != nil {
			return err
		}
		ssrRunning = true
		go func() {
			if err := SsrCmd.Wait(); err != nil {
				log.Println(err)
			}
			ssrRunning = false
		}()

		_ = MatchCon.SetAllOption(func(option *controller.OptionMatchCon) {
			option.Proxy = func(host string) (conn net.Conn, err error) {
				return socks5client.NewSocks5Client(localHost, "", "", host)
			}
		})
	default:
		return errors.New("no support type proxy")
	}
	return nil
}
