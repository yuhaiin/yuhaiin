package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var y *yhCli

func main() {
	cobra.OnInitialize(func() {
		host, err := ioutil.ReadFile(filepath.Join(config.DefaultConfigDir(), "yuhaiin.lock_payload"))
		if err != nil {
			panic(err)
		}
		y, err = NewCli(string(host))
		if err != nil {
			panic(err)
		}
	})

	rootCmd := cobra.Command{
		Use:   "yh",
		Short: "a cli client for yuhaiin",
	}
	rootCmd.AddCommand(nodeCmd(), latencyCmd(), streamCmd(), subCmd(), listCmd(), configCmd(), connCmd())
	rootCmd.Execute()
}

func latencyCmd() *cobra.Command {
	latency := &cobra.Command{
		Use:   "lat",
		Short: "get node latency",
		Long: `lat <group index> <node index> OR lat -g <group index> -n <node index>, test node latency of group index and node index
lat <hash> OR lat -s <hash>, test node latency of node hash`,
		Example: `lat 0 0
lat -g 0 -n 0
lat 5322574f8337b90440650c0d7c4a2427d2194b6cefc916f859e6656f1b0e797d
lat -s 5322574f8337b90440650c0d7c4a2427d2194b6cefc916f859e6656f1b0e797d`,
		Run: func(cmd *cobra.Command, args []string) {
			specifiedGN(cmd, args,
				func(s string) {
					y.latency(s)
				},
				func(i1, i2 int) {
					y.latencyWithGroupAndNode(i1, i2)
				},
			)
		},
	}
	latency.Flags().StringP("hash", "s", "", "hash of node")
	latency.Flags().IntP("group", "g", -1, "group index")
	latency.Flags().IntP("node", "n", -1, "node index")

	all := &cobra.Command{
		Use:     "all",
		Long:    "get all node of a group latency,eg: all [group index]",
		Example: "all 0",
		Run: func(cmd *cobra.Command, args []string) {
			i, err := strconv.Atoi(args[0])
			if err != nil {
				log.Println(err)
				return
			}

			y.latencyAll(i)
		},
	}
	latency.AddCommand(all)

	return latency
}

func streamCmd() *cobra.Command {
	streamCmd := &cobra.Command{
		Use:   "data",
		Short: "see stream data",
		Run: func(cmd *cobra.Command, args []string) {
			y.streamData()
		},
	}

	return streamCmd
}

func subCmd() *cobra.Command {
	subCmd := &cobra.Command{
		Use: "sub",
	}

	update := &cobra.Command{
		Use:     "update",
		Long:    "update all subscription",
		Example: "update",
		Run: func(cmd *cobra.Command, args []string) {
			y.updateSub()
		},
	}

	add := &cobra.Command{
		Use:     "add",
		Long:    "add new subscription, add [name] [url] [type]",
		Example: `add test_link https://example.com`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 2 {
				log.Println("incorrect arguments")
				return
			}
			var t int
			if len(args) == 3 {
				t, _ = strconv.Atoi(args[2])
			}

			if len(args) == 2 {
				_, err := y.sub.SaveLinks(context.TODO(),
					&node.SaveLinkReq{
						Links: []*node.NodeLink{
							{
								Name: args[0],
								Url:  args[1],
								Type: node.NodeLinkLinkType(t),
							},
						},
					},
				)
				if err != nil {
					log.Println("add link failed:", err)
					return
				}
			}
		},
	}

	ls := &cobra.Command{
		Use:  "ls",
		Long: "list all subscription link",
		Run: func(cmd *cobra.Command, args []string) {
			n, err := y.sub.GetLinks(context.Background(), &emptypb.Empty{})
			if err != nil {
				log.Println("get nodes failed:", err)
				return
			}

			for _, v := range n.Links {
				fmt.Println(v.Name, v.Url, v.Type)
			}
		},
	}

	subCmd.AddCommand(ls, update, add)

	return subCmd
}

func listCmd() *cobra.Command {
	ls := &cobra.Command{
		Use:   "ls",
		Short: "list node info",
		Long: `ls, list all groups
ls all, list all groups and nodes
ls now, show now node info
ls <group index>, list nodes of group index 
ls <group index> <node index>, show node info of group index and node index`,
		Example: `ls
ls all
ls now
ls 0
ls 0 0`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				y.group()
			}

			if len(args) == 1 && args[0] == "all" {
				y.listAll()
				return
			}

			if len(args) == 1 && args[0] == "now" {
				y.nowNode()
				return
			}

			if len(args) == 1 {
				i, err := strconv.Atoi(args[0])
				if err != nil {
					y.nodeInfo(args[0])
					return
				}

				y.nodes(i)
			}

			if len(args) == 2 {
				i, err := strconv.Atoi(args[0])
				if err != nil {
					log.Println(err)
					return
				}
				z, err := strconv.Atoi(args[1])
				if err != nil {
					log.Println(err)
					return
				}

				err = y.nodeInfoWithGroupAndNode(i, z)
				if err != nil {
					log.Println(err)
				}
			}
		},
	}

	return ls
}

func nodeCmd() *cobra.Command {
	nodeCmd := &cobra.Command{
		Use: "node",
	}

	use := &cobra.Command{
		Use:  "use",
		Long: "use a node",
		Example: `use xasfssgtrt5435342q3wdf233e3f
use 0 0
		`,
		Run: func(cmd *cobra.Command, args []string) {
			specifiedGN(cmd, args,
				func(s string) {
					y.changeNowNode(s)
				},
				func(i1, i2 int) {
					y.changeNowNodeWithGroupAndNode(i1, i2)
				},
			)
		},
	}
	use.Flags().StringP("hash", "s", "", "hash of node")
	use.Flags().IntP("group", "g", -1, "group index")
	use.Flags().IntP("node", "n", -1, "node index")

	set := &cobra.Command{
		Use:  "set",
		Long: "set one node config",
		Example: `set zxcdfarewr43fregret43g vmess.address=example.com
set 0 0 vmess.address=example
		`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 2 {
				err := y.setNodeConfig(args[0], args[1])
				if err != nil {
					log.Println(err)
				}
			}
			if len(args) == 3 {
				i, err := strconv.Atoi(args[0])
				if err != nil {
					log.Println(err)
					return
				}
				z, err := strconv.Atoi(args[1])
				if err != nil {
					log.Println(err)
					return
				}
				err = y.setNodeConfigWithGroupAndNode(i, z, args[2])
				if err != nil {
					log.Println(err)
				}
			}
		},
	}

	nodeCmd.AddCommand(use)
	nodeCmd.AddCommand(set)

	return nodeCmd
}

func configCmd() *cobra.Command {
	configCmd := &cobra.Command{
		Use:  "config",
		Long: "list config",
		Run: func(cmd *cobra.Command, args []string) {
			y.showConfig()
		},
	}

	set := &cobra.Command{
		Use:     "set",
		Long:    "set config",
		Example: "set dns.remote.host=1.1.1.1",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				log.Println("args length is not 1")
				return
			}

			err := y.setConfig(args[0])
			if err != nil {
				log.Println("set config failed:", err)
			}
		},
	}

	configCmd.AddCommand(set)

	return configCmd
}

func connCmd() *cobra.Command {
	connCmd := &cobra.Command{
		Use: "conn",
	}

	list := &cobra.Command{
		Use:  "ls",
		Long: "list all exist connections",
		Run: func(cmd *cobra.Command, args []string) {
			y.listConns()
		},
	}

	close := &cobra.Command{
		Use:  "close",
		Long: "clone connections, close [connection id]",
		Example: `close 123 124 125
close all
		`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 && args[0] == "all" {
				y.closeAllConns()
				return
			}

			var ids []int64
			for i := range args {
				z, err := strconv.ParseInt(args[i], 10, 64)
				if err != nil {
					log.Println(err)
					continue
				}

				ids = append(ids, z)
			}

			y.closeConns(ids...)
		},
	}

	connCmd.AddCommand(list, close)

	return connCmd
}

func specifiedGN(cmd *cobra.Command, args []string, f1 func(string), f2 func(int, int)) {
	hash, _ := cmd.Flags().GetString("hash")
	group, _ := cmd.Flags().GetInt("group")
	node, _ := cmd.Flags().GetInt("node")

	if hash == "" && group == -1 && node == -1 {
		if len(args) == 1 {
			hash = args[0]
		} else if len(args) == 2 {
			var err error
			group, err = strconv.Atoi(args[0])
			if err != nil {
				return
			}
			node, err = strconv.Atoi(args[1])
			if err != nil {
				return
			}
		}
	}

	if hash != "" {
		f1(hash)
	}

	if group != -1 && node != -1 {
		f2(group, node)
	}
}

type yhCli struct {
	conn *grpc.ClientConn
	cm   statistic.ConnectionsClient
	sub  node.NodeManagerClient
	cg   config.ConfigDaoClient
}

func NewCli(host string) (*yhCli, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*10)
	defer cancel()
	conn, err := grpc.DialContext(ctx, string(host), grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("grpc dial failed: %w", err)
	}

	cm := statistic.NewConnectionsClient(conn)
	sub := node.NewNodeManagerClient(conn)
	cg := config.NewConfigDaoClient(conn)
	return &yhCli{conn: conn, cm: cm, sub: sub, cg: cg}, nil
}

func (y *yhCli) streamData() {
	sts, err := y.cm.Statistic(context.Background(), &emptypb.Empty{})
	if err != nil {
		panic(err)
	}

	ctx := sts.Context()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		resp, err := sts.Recv()
		if err != nil {
			break
		}

		s := fmt.Sprintf("D(%s):%s U(%s):%s", resp.Download, resp.DownloadRate, resp.Upload, resp.UploadRate)

		fmt.Printf("%s%s\r", s, strings.Repeat(" ", 47-len(s)))
	}
}

func (y *yhCli) listAll() error {
	ns, err := y.sub.GetManager(context.Background(), &wrapperspb.StringValue{})
	if err != nil {
		return fmt.Errorf("get node failed: %w", err)
	}
	for i := range ns.Groups {
		fmt.Println(i, ns.Groups[i])
		for z := range ns.GroupNodesMap[ns.Groups[i]].Nodes {
			node := ns.GroupNodesMap[ns.Groups[i]].Nodes[z]
			fmt.Println("\t", z, node, "hash:", ns.GroupNodesMap[ns.Groups[i]].NodeHashMap[node])
		}
	}

	return nil
}

func (y *yhCli) group() error {
	ns, err := y.sub.GetManager(context.Background(), &wrapperspb.StringValue{})
	if err != nil {
		return fmt.Errorf("get node failed: %w", err)
	}

	for i := range ns.Groups {
		fmt.Println(i, ns.Groups[i])
	}
	return nil
}

func (y *yhCli) nodes(i int) error {
	ns, err := y.sub.GetManager(context.Background(), &wrapperspb.StringValue{})
	if err != nil {
		return fmt.Errorf("get node failed: %w", err)
	}

	if i >= len(ns.Groups) || i < 0 {
		return nil
	}

	for z := range ns.GroupNodesMap[ns.Groups[i]].Nodes {
		node := ns.GroupNodesMap[ns.Groups[i]].Nodes[z]
		fmt.Println(z, node, "hash:", ns.GroupNodesMap[ns.Groups[i]].NodeHashMap[node])
	}
	return nil
}

func (y *yhCli) latencyWithGroupAndNode(i, z int) error {
	hash, err := y.getHash(i, z)
	if err != nil {
		return fmt.Errorf("get hash failed: %w", err)
	}
	return y.latency(hash)
}

func (y *yhCli) getHash(i, z int) (string, error) {
	ns, err := y.sub.GetManager(context.Background(), &wrapperspb.StringValue{})
	if err != nil {
		return "", fmt.Errorf("get node failed: %w", err)
	}

	if i >= len(ns.Groups) || i < 0 {
		return "", fmt.Errorf("group index error")
	}

	group := ns.Groups[i]

	if z >= len(ns.GroupNodesMap[group].Nodes) || z < 0 {
		return "", fmt.Errorf("node index error")
	}

	node := ns.GroupNodesMap[group].Nodes[z]

	return ns.GroupNodesMap[group].NodeHashMap[node], nil
}

func (y *yhCli) latency(hash string) error {
	l, err := y.sub.Latency(context.Background(), &node.LatencyReq{NodeHash: []string{hash}})
	if err != nil {
		return fmt.Errorf("get latency failed: %w", err)
	}
	fmt.Println(l.HashLatencyMap[hash])
	return nil
}

func (y *yhCli) latencyAll(i int) {
	ns, err := y.sub.GetManager(context.Background(), &wrapperspb.StringValue{})
	if err != nil {
		log.Printf("get node failed: %v\n", err)
		return
	}

	if i >= len(ns.Groups) {
		return
	}

	group := ns.GroupNodesMap[ns.Groups[i]]

	wg := sync.WaitGroup{}
	for _, z := range group.Nodes {
		wg.Add(1)
		go func(name, hash string) {
			defer wg.Done()
			l, err := y.sub.Latency(context.TODO(), &node.LatencyReq{NodeHash: []string{hash}})
			if err != nil {
				fmt.Printf("%s: %v\n", name, err)
				return
			}

			latency := "test timeout or can't connect"
			if z, ok := l.HashLatencyMap[hash]; ok {
				latency = z.Tcp
			}

			fmt.Printf("%s: %s | %s\n", name, latency, hash)
		}(z, group.NodeHashMap[z])
	}

	wg.Wait()
}

func (y *yhCli) changeNowNodeWithGroupAndNode(i, z int) error {
	ns, err := y.sub.GetManager(context.Background(), &wrapperspb.StringValue{})
	if err != nil {
		return fmt.Errorf("get node failed: %w", err)
	}

	if i >= len(ns.Groups) {
		return nil
	}

	group := ns.Groups[i]
	if z >= len(ns.GroupNodesMap[group].Nodes) {
		return nil
	}

	node := ns.GroupNodesMap[group].Nodes[z]

	return y.changeNowNode(ns.GroupNodesMap[group].NodeHashMap[node])
}

func (y *yhCli) changeNowNode(hash string) error {
	l, err := y.sub.Use(context.Background(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		return fmt.Errorf("change now node failed: %w", err)
	}
	d, _ := protojson.MarshalOptions{Indent: "\t"}.Marshal(l)
	fmt.Println(string(d))
	return nil
}

func (y *yhCli) nowNode() error {
	n, err := y.sub.Now(context.Background(), &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("get now node failed: %w", err)
	}

	fmt.Println("name ", n.Name)
	fmt.Println("group", n.Group)
	fmt.Println("hash ", n.Hash)
	return nil
}

func (y *yhCli) updateSub() error {
	n, err := y.sub.GetLinks(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("get node failed: %w", err)
	}

	req := &node.LinkReq{}
	for _, link := range n.GetLinks() {
		req.Names = append(req.Names, link.Name)
	}
	_, err = y.sub.UpdateLinks(context.Background(), req)
	return err
}

func (y *yhCli) nodeInfoWithGroupAndNode(i, z int) error {
	hash, err := y.getHash(i, z)
	if err != nil {
		return fmt.Errorf("get hash failed: %w", err)
	}
	return y.nodeInfo(hash)
}

func (y *yhCli) nodeInfo(hash string) error {
	node, err := y.sub.GetNode(context.Background(), wrapperspb.String(hash))
	if err != nil {
		return fmt.Errorf("get node failed: %w", err)
	}

	fmt.Println(protojson.MarshalOptions{Indent: "\t", UseProtoNames: true, EmitUnpopulated: true}.Format(node))
	return nil
}

func (y *yhCli) setNodeConfigWithGroupAndNode(i, z int, set string) error {
	hash, err := y.getHash(i, z)
	if err != nil {
		return fmt.Errorf("get hash failed: %w", err)
	}
	return y.setNodeConfig(hash, set)
}

func (y *yhCli) setNodeConfig(hash string, setting string) error {
	node, err := y.sub.GetNode(context.Background(), wrapperspb.String(hash))
	if err != nil {
		return fmt.Errorf("get node failed: %w", err)
	}

	data := protojson.MarshalOptions{Indent: "\t", UseProtoNames: true, EmitUnpopulated: true}.Format(node)

	var s map[string]interface{}
	err = json.Unmarshal([]byte(data), &s)
	if err != nil {
		return fmt.Errorf("unmarshal failed: %w", err)
	}

	kv := strings.Split(setting, "=")
	if len(kv) != 2 {
		return fmt.Errorf("")
	}

	key := kv[0]
	value := kv[1]

	parts := strings.Split(key, ".")
	err = set(s, parts, value)
	if err != nil {
		return fmt.Errorf("set value failed: %w", err)
	}

	jsonStr, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("json marshal failed: %w", err)
	}

	err = protojson.Unmarshal(jsonStr, node)
	if err != nil {
		return fmt.Errorf("protojson unmarshal failed: %w", err)
	}

	point, err := y.sub.SaveNode(context.TODO(), node)
	if err != nil {
		return fmt.Errorf("save setting failed: %w", err)
	}
	fmt.Println(protojson.MarshalOptions{Indent: "\t", EmitUnpopulated: true}.Format(point))
	return nil
}

func (y *yhCli) showConfig() error {
	c, err := y.cg.Load(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("load config failed: %w", err)
	}

	fmt.Println(protojson.MarshalOptions{Indent: "\t", EmitUnpopulated: true}.Format(c))
	return nil
}

func (y *yhCli) setConfig(setting string) error {
	c, err := y.cg.Load(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("load config failed: %w", err)
	}

	data := protojson.MarshalOptions{Indent: "\t", EmitUnpopulated: true}.Format(c)

	var s map[string]interface{}
	err = json.Unmarshal([]byte(data), &s)
	if err != nil {
		return fmt.Errorf("unmarshal failed: %w", err)
	}

	kv := strings.Split(setting, "=")
	if len(kv) != 2 {
		return fmt.Errorf("")
	}

	key := kv[0]
	value := kv[1]

	parts := strings.Split(key, ".")
	err = set(s, parts, value)
	if err != nil {
		return fmt.Errorf("set value failed: %w", err)
	}

	jsonStr, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("json marshal failed: %w", err)
	}

	err = protojson.Unmarshal(jsonStr, c)
	if err != nil {
		return fmt.Errorf("protojson unmarshal failed: %w", err)
	}

	_, err = y.cg.Save(context.TODO(), c)
	if err != nil {
		return fmt.Errorf("save setting failed: %w", err)
	}

	return y.showConfig()
}

func set(s map[string]interface{}, k []string, v string) error {
	l := len(k) - 1
	for i := 0; i < l; i++ {
		v, ok := s[k[i]].(map[string]interface{})
		if !ok {
			return fmt.Errorf("can't find key %v", k[i])
		}

		s = v
	}

	var b interface{}
	var err error
	switch s[k[l]].(type) {
	case bool:
		b, err = strconv.ParseBool(v)
	case string:
		b = v
	case int64:
		b, err = strconv.ParseInt(v, 0, 64)
	default:
		fmt.Println("unknow type", s[k[l]])
	}
	if err != nil {
		return fmt.Errorf("parse value failed: %w", err)
	}
	s[k[l]] = b
	return nil
}

func (y *yhCli) listConns() error {
	c, err := y.cm.Conns(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("get conns failed: %w", err)
	}

	sort.Slice(c.Connections, func(i, j int) bool { return c.Connections[i].Id < c.Connections[j].Id })

	for i := range c.Connections {
		fmt.Println(c.Connections[i].Id, c.Connections[i].Addr, "|", fmt.Sprintf("%s <-> %s", c.Connections[i].Local, c.Connections[i].Remote))
	}

	return nil
}

func (y *yhCli) closeConns(id ...int64) {
	_, _ = y.cm.CloseConn(context.TODO(), &statistic.CloseConnsReq{Conns: id})
}

func (y *yhCli) closeAllConns() error {
	c, err := y.cm.Conns(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("get conns failed: %w", err)
	}

	ids := make([]int64, 0, len(c.Connections))
	for _, i := range c.Connections {
		ids = append(ids, i.Id)
	}

	_, err = y.cm.CloseConn(context.TODO(), &statistic.CloseConnsReq{Conns: ids})
	return err
}
