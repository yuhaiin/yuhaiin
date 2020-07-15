package process

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
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
	ssrCtx    context.Context
	ssrCancel context.CancelFunc
	nowNode   string
)

func ChangeNode() error {
	nNode, err := GetNowNode()
	if err != nil {
		return err
	}

	hashSum, same := checkSame(nNode)
	if same {
		return nil
	}

	if ssrCtx != nil {
	_check:
		select {
		case <-ssrCtx.Done():
			break
		default:
			ssrCancel()
			goto _check
		}
	}
	switch nNode.(type) {
	case *subscr.Shadowsocks:
		n := nNode.(*subscr.Shadowsocks)
		fmt.Println("Start Shadowsocks", hashSum)
		conn, err := client.NewShadowsocks(
			n.Method,
			n.Password,
			n.Server, n.Port,
			n.Plugin,
			n.PluginOpt,
		)
		if err != nil {
			return err
		}
		nowNode = hashSum
		_ = MatchCon.SetAllOption(func(option *controller.OptionMatchCon) {
			option.Proxy = conn.Conn
		})
	case *subscr.Shadowsocksr:
		fmt.Println("Start Shadowsocksr", hashSum)
		ssrCtx, ssrCancel = context.WithCancel(context.Background())
		SsrCmd, localHost, err := controller.ShadowsocksrCmd(ssrCtx, nNode.(*subscr.Shadowsocksr), ConFig.SsrPath)
		if err != nil {
			return err
		}
		if err := SsrCmd.Start(); err != nil {
			return err
		}
		go func() {
			err := SsrCmd.Wait()
			if err != nil {
				log.Println(err)
			}
			fmt.Println("Kill Shadowsocksr running exec Command")
		}()

		nowNode = hashSum
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

func checkSame(nNode interface{}) (string, bool) {
	var hashSum string
	switch nNode.(type) {
	case *subscr.Shadowsocks:
		n := nNode.(*subscr.Shadowsocks)
		hash := md5.New()
		hash.Write([]byte(n.Server))
		hash.Write([]byte(n.Port))
		hash.Write([]byte(n.Password))
		hash.Write([]byte{byte(n.Type)})
		hash.Write([]byte(n.Group))
		hash.Write([]byte(n.Name))
		hash.Write([]byte(n.Plugin))
		hash.Write([]byte(n.PluginOpt))
		hashSum = hex.EncodeToString(hash.Sum(nil))
		if nowNode == hashSum {
			return hashSum, true
		}
	case *subscr.Shadowsocksr:
		n := nNode.(*subscr.Shadowsocksr)
		hash := md5.New()
		hash.Write([]byte(n.Server))
		hash.Write([]byte(n.Port))
		hash.Write([]byte(n.Password))
		hash.Write([]byte{byte(n.Type)})
		hash.Write([]byte(n.Group))
		hash.Write([]byte(n.Name))
		hash.Write([]byte(n.Obfs))
		hash.Write([]byte(n.Obfsparam))
		hash.Write([]byte(n.Protocol))
		hash.Write([]byte(n.Protoparam))
		hash.Write([]byte(ConFig.SsrPath))
		hashSum = hex.EncodeToString(hash.Sum(nil))
		if nowNode == hashSum {
			return hashSum, true
		}
	}
	return hashSum, false
}
