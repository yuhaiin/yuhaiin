package configJSON

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"../../base64d"
	"../../subscription"
)

// 待测试 https://github.com/evanphx/json-patch

type Node struct {
	ID         int    `json:"id"`
	Server     string `json:"server"`
	ServerPort string `json:"serverPort"`
	Protocol   string `json:"protocol"`
	Method     string `json:"method"`
	Obfs       string `json:"obfs"`
	Password   string `json:"password"`
	Obfsparam  string `json:"obfsparam"`
	Protoparam string `json:"protoparam"`
	Remarks    string `json:"remarks"`
	Group      string `json:"group"`
}

type Path struct {
	PYTHONPATH string `json:"pythonPath"`
	SSRPATH    string `json:"ssrPath"`
	PIDFILE    string `json:"pidFath"`
	LOGFILE    string `json:"logFath"`
}

type ConfigSample struct {
	Group   map[string]bool            `json:"group"`
	NowNode Node                       `json:"nowNode"`
	Link    []string                   `json:"link"`
	Node    map[string]map[string]Node `json:"node"`
}

// InitJSON init the config json file
func InitJSON(configPath string) error {
	pa := &ConfigSample{
		Group:   map[string]bool{},
		NowNode: Node{},
		Link:    []string{},
		Node:    map[string]map[string]Node{},
	}
	if err := enCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

func decodeJSON(configPath string) (*ConfigSample, error) {
	pa := &ConfigSample{}
	file, err := os.Open(configPath + "/node.json")
	if err != nil {
		return &ConfigSample{}, err
	}
	if json.NewDecoder(file).Decode(&pa) != nil {
		return &ConfigSample{}, err
	}
	return pa, nil
}

func enCodeJSON(configPath string, pa *ConfigSample) error {
	file, err := os.Create(configPath + "/node.json")
	if err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(&pa); err != nil {
		return err
	}
	return nil
}

// GetLinkFromInt <--
func GetLinkFromInt(configPath string) ([]string, error) {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return []string{}, err
	}
	var allLink string
	for _, url := range pa.Link {
		res, err := http.Get(url)
		if err != nil {
			return []string{}, err
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []string{}, err
		}
		allLink += base64d.Base64d(string(body))
	}
	return strings.Split(allLink, "\n"), nil
}

func addLinkJSON(link, configPath string) error {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return err
	}
	pa.Link = append(pa.Link, link)
	if err := enCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

// AddLinkJSON for other package to add link
func AddLinkJSON(configPath string) error {
	var link string
	fmt.Scanln(&link)
	addLinkJSON(link, configPath)
	return nil
}

func removeLinkJSON(link, configPath string) error {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return err
	}
	for num, oneLink := range pa.Link {
		if link == oneLink {
			pa.Link = append(pa.Link[:num], pa.Link[num+1:]...)
			break
		}
	}
	if err := enCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

// RemoveLinkJSON remove link for other package
func RemoveLinkJSON(configPath string) error {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return err
	}
	var linkSum int
	var link string
	for linkSum, link = range pa.Link {
		fmt.Println(strconv.Itoa(linkSum+1) + "." + link)
	}
	var num int
	if _, err = fmt.Scanln(&num); err != nil {
		return err
	}

	if num < 1 || num > linkSum+1 {
		return nil
	}
	if err := removeLinkJSON(pa.Link[num-1], configPath); err != nil {
		return err
	}
	return nil
}

// SsrJSON reset all node from link
func SsrJSON(configPath string) error {
	// ssrB := []string{"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz02YUtkNW9HcDZMcXImZ3JvdXA9NmFLZDVvR3A2THFy",
	// 	"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz1jMlZqYjI1ayZncm91cD02YUtkNW9HcDZMcXIK",
	// 	"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz1jM056YzNOeiZncm91cD1jM056YzNOego"}
	pa, err := decodeJSON(configPath)
	if err != nil {
		return err
	}
	allNode, err := GetLinkFromInt(configPath)
	if err != nil {
		return err
	}
	for num, oneNode := range allNode {
		nodeGet, err := subscription.GetNode(oneNode)
		if err != nil {
			return err
		}
		if len(nodeGet) == 0 {
			continue
		}
		nodeJSON := &Node{
			ID:         num,
			Server:     nodeGet["server"],
			ServerPort: nodeGet["serverPort"],
			Protocol:   nodeGet["protocol"],
			Method:     nodeGet["method"],
			Obfs:       nodeGet["obfs"],
			Password:   nodeGet["password"],
			Obfsparam:  nodeGet["obfsparam"],
			Protoparam: nodeGet["protoparam"],
			Remarks:    nodeGet["remarks"],
			Group:      nodeGet["group"],
		}
		if !pa.Group[nodeJSON.Group] {
			pa.Group[nodeJSON.Group] = true
		}
		if _, ok := pa.Node[nodeJSON.Group]; !ok { //judge map key is exist or not
			pa.Node[nodeJSON.Group] = map[string]Node{}
		}
		pa.Node[nodeJSON.Group][nodeJSON.Remarks] = *nodeJSON
	}
	// js, err := json.MarshalIndent(pa, "", "\t")
	// if err != nil {
	// 	return err
	// }
	// log.Println(pa)
	// log.Println(string(js))
	if err := enCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

// SelectNode <--
func SelectNode(configPath string) (Node, error) {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return Node{}, err
	}
selectgroup:
	groupTmp := make(map[int]string)
	num := 1
	for group := range pa.Node {
		fmt.Println(num, group)
		groupTmp[num] = group
		num++
	}
	var selectGroup int
	fmt.Scanln(&selectGroup)
	if selectGroup < 0 || selectGroup > num-1 {
		fmt.Println("select error")
		goto selectgroup
	} else if selectGroup == 0 {
		return Node{}, nil
	} else {
	selectnode:
		num = 1
		nodeTmp := make(map[int]string)
		for nodeRemarks := range pa.Node[groupTmp[selectGroup]] {
			fmt.Println(num, nodeRemarks)
			nodeTmp[num] = nodeRemarks
			num++
		}
		var selectNode int
		fmt.Scanln(&selectNode)
		if selectNode < 0 || selectNode > num-1 {
			fmt.Println("select error")
			goto selectnode
		} else if selectNode == 0 {
			goto selectgroup
		} else {
			return pa.Node[groupTmp[selectGroup]][nodeTmp[selectNode]], nil
		}
	}
}

// ChangeNowNode <--
func ChangeNowNode(configPath string) error {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return err
	}
	node, err := SelectNode(configPath)
	if err != nil {
		return err
	}
	if node.Server == "" {
		return nil
	}
	pa.NowNode = node
	if err := enCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

// GetNowNode <--
func GetNowNode(configPath string) (map[string]string, error) {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return map[string]string{}, err
	}
	node := make(map[string]string)
	node["remarks"] = pa.NowNode.Remarks
	node["server"] = pa.NowNode.Server
	node["serverPort"] = pa.NowNode.ServerPort
	node["protocol"] = pa.NowNode.Protocol
	node["method"] = pa.NowNode.Method
	node["obfs"] = pa.NowNode.Obfs
	node["password"] = pa.NowNode.Password
	node["obfsparam"] = pa.NowNode.Obfsparam
	node["protoparam"] = pa.NowNode.Protoparam
	return node, nil
}

func main() {

	// ssrJSON("/media/asutorufa/D/code/golang/SsrMicroClient/config/test/configJson")

	// pa, _ := decodeJSON("/media/asutorufa/D/code/golang/SsrMicroClient/config/test/configJson")
	// for group := range pa.Group {
	// 	log.Println(group)
	// 	for remarks := range pa.Node[group] {
	// 		log.Println(pa.Node[group][remarks])
	// 	}
	// }

	path := "/media/asutorufa/D/code/golang/SsrMicroClient/config/test/configJson"
	// InitJSON(path)
	// addLinkJSON("test", path)
	// addLinkJSON("test2", path)
	// addLinkJSON("test3", path)
	// addLinkJSON("test4", path)
	// RemoveLinkJSON(path)

	// ssrJSON(path)

	ChangeNowNode(path)

}

// ---------------------------------------------------old------------------------
// func encodeJSON() {
// 	ds := []string{"ss", "dd"}
// 	nodeTest := node{
// 		ID:         1,
// 		Server:     "1.1.1.1",
// 		ServerPort: "1080",
// 		Protocol:   "auth_",
// 		Method:     "chacha",
// 		Obfs:       "obfs",
// 		Password:   "fff",
// 		Obfsparam:  "sss",
// 		Protoparam: "sss",
// 		Remarks:    "sss",
// 		Group:      "sss",
// 	}
// 	pa := &configSample{
// 		Group:   map[string]bool{},
// 		NowNode: nodeTest,
// 		Link:    ds,
// 		Node:    map[string]map[string]node{},
// 	}
// 	link := "sss"
// 	pa.Link = append(pa.Link, link)
// 	// pa.Node[nodeTest.Group] = append(pa.Node[nodeTest.Group], nodeTest)
// 	pa.Node[nodeTest.Group] = map[string]node{}
// 	pa.Node[nodeTest.Group][nodeTest.Remarks] = nodeTest
// 	js, _ := json.MarshalIndent(pa, "", "\t")
// 	s := &configSample{}
// 	json.Unmarshal(js, s)
// 	fmt.Printf("JSON format: %s\n", js)
// 	log.Println(s)

// 	file, _ := os.Create("/media/asutorufa/D/code/golang/SsrMicroClient/config/test/configJson/a.json")
// 	enc := json.NewEncoder(file)
// 	enc.Encode(&pa)
// }
