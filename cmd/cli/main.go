package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func defaultConfigDir() (Path string) {
	var err error
	Path, err = os.UserConfigDir()
	if err == nil {
		Path = path.Join(Path, "yuhaiin")
		return
	}

	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		log.Println(err)
		Path = "./yuhaiin"
		return
	}
	execPath, err := filepath.Abs(file)
	if err != nil {
		log.Println(err)
		Path = "./yuhaiin"
		return
	}
	Path = path.Join(filepath.Dir(execPath), "config")
	return
}

func main() {
	host, err := ioutil.ReadFile(filepath.Join(defaultConfigDir(), "yuhaiin.lock_payload"))
	if err != nil {
		panic(err)
	}

	y, err := NewCli(string(host))
	if err != nil {
		panic(err)
	}

	rootCmd := cobra.Command{
		Use:   "yh",
		Short: "a cli client for yuhaiin",
		Long:  "",
	}

	rootCmd.AddCommand(nodeCmd(y), latencyCmd(y), streamCmd(y), subCmd(y))
	rootCmd.Execute()
}

func latencyCmd(y *yhCli) *cobra.Command {
	latency := &cobra.Command{
		Use:   "lat",
		Short: "get node latency",
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
	return latency
}

func streamCmd(y *yhCli) *cobra.Command {
	streamCmd := &cobra.Command{
		Use: "data",
		Run: func(cmd *cobra.Command, args []string) {
			y.streamData()
		},
	}

	return streamCmd
}

func subCmd(y *yhCli) *cobra.Command {
	subCmd := &cobra.Command{
		Use: "sub",
	}

	update := &cobra.Command{
		Use: "update",
		Run: func(cmd *cobra.Command, args []string) {
			y.updateSub()
		},
	}

	subCmd.AddCommand(update)

	return subCmd
}
func nodeCmd(y *yhCli) *cobra.Command {
	nodeCmd := &cobra.Command{
		Use: "node",
	}

	group := &cobra.Command{
		Use: "group",
		Run: func(cmd *cobra.Command, args []string) {
			y.group()
		},
	}

	nodes := &cobra.Command{
		Use: "ls",
		Run: func(cmd *cobra.Command, args []string) {
			i, _ := cmd.Flags().GetInt("index")
			if i == -1 {
				if len(args) <= 0 {
					return
				}

				var err error
				i, err = strconv.Atoi(args[0])
				if err != nil {
					return
				}
			}

			y.nodes(i)
		},
	}
	nodes.Flags().IntP("index", "i", -1, "group index")

	now := &cobra.Command{
		Use: "now",
		Run: func(cmd *cobra.Command, args []string) {
			y.nowNode()
		},
	}

	use := &cobra.Command{
		Use: "use",
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

	info := &cobra.Command{
		Use: "info",
		Run: func(cmd *cobra.Command, args []string) {
			specifiedGN(cmd, args,
				func(s string) {
					y.nodeInfo(s)
				},
				func(i1, i2 int) {
					y.nodeInfoWithGroupAndNode(i1, i2)
				},
			)

		},
	}
	info.Flags().StringP("hash", "s", "", "hash of node")
	info.Flags().IntP("group", "g", -1, "group index")
	info.Flags().IntP("node", "n", -1, "node index")

	nodeCmd.AddCommand(group, nodes, now, use, info)

	return nodeCmd
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
	cm   app.ConnectionsClient
	sub  subscr.NodeManagerClient
}

func NewCli(host string) (*yhCli, error) {
	conn, err := grpc.Dial(string(host), grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("grpc dial failed: %w", err)
	}

	cm := app.NewConnectionsClient(conn)
	sub := subscr.NewNodeManagerClient(conn)
	return &yhCli{conn: conn, cm: cm, sub: sub}, nil
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

		fmt.Printf("\r%v             ", resp)
	}
}

func (y *yhCli) group() error {
	ns, err := y.sub.GetNodes(context.Background(), &wrapperspb.StringValue{})
	if err != nil {
		return fmt.Errorf("get node failed: %w", err)
	}

	for i := range ns.Groups {
		fmt.Println(i, ns.Groups[i])
	}
	return nil
}

func (y *yhCli) nodes(i int) error {
	ns, err := y.sub.GetNodes(context.Background(), &wrapperspb.StringValue{})
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
	ns, err := y.sub.GetNodes(context.Background(), &wrapperspb.StringValue{})
	if err != nil {
		return fmt.Errorf("get node failed: %w", err)
	}

	if i >= len(ns.Groups) || i < 0 {
		return nil
	}

	group := ns.Groups[i]
	if z >= len(ns.GroupNodesMap[group].Nodes) || z < 0 {
		return nil
	}

	node := ns.GroupNodesMap[group].Nodes[z]
	fmt.Println(group, node)
	return y.latency(ns.GroupNodesMap[group].NodeHashMap[node])
}

func (y *yhCli) latency(hash string) error {
	l, err := y.sub.Latency(context.Background(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		return fmt.Errorf("get latency failed: %w", err)
	}
	fmt.Println(l.Value)
	return nil
}

func (y *yhCli) changeNowNodeWithGroupAndNode(i, z int) error {
	ns, err := y.sub.GetNodes(context.Background(), &wrapperspb.StringValue{})
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
	l, err := y.sub.ChangeNowNode(context.Background(), &wrapperspb.StringValue{Value: hash})
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

	fmt.Println("name ", n.NName)
	fmt.Println("group", n.NGroup)
	fmt.Println("hash ", n.NHash)
	return nil
}

func (y *yhCli) updateSub() error {
	_, err := y.sub.RefreshSubscr(context.Background(), &emptypb.Empty{})
	return err
}

func (y *yhCli) nodeInfoWithGroupAndNode(i, z int) error {
	ns, err := y.sub.GetNodes(context.Background(), &wrapperspb.StringValue{})
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

	return y.nodeInfo(ns.GroupNodesMap[group].NodeHashMap[node])
}

func (y *yhCli) nodeInfo(hash string) error {
	node, err := y.sub.GetNode(context.Background(), wrapperspb.String(hash))
	if err != nil {
		return fmt.Errorf("get node failed: %w", err)
	}

	d, _ := protojson.MarshalOptions{Indent: "\t"}.Marshal(node)
	fmt.Println(string(d))
	return nil
}
