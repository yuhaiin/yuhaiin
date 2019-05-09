package subscription

import (
	"fmt"
	"regexp"

	"../base64d"
)

type err struct {
	err string
}

func (e err) Error() string {
	return fmt.Sprintf(e.err)
}

func ssRe(str string) (map[string]string, error) {
	ssRe, _ := regexp.Compile("(.*):(.*)@(.*):([0-9]*)")
	node := map[string]string{}
	ss := ssRe.FindAllStringSubmatch(base64d.Base64d(str), -1)
	if len(ss) != 0 {
		node["template"] = "ss"
		node["method"] = ss[0][1]
		node["password"] = base64d.Base64d(ss[0][2])
		node["server"] = ss[0][3]
		node["serverPort"] = ss[0][4]
	} else {
		// log.Println("this link is not ssr link!", base64d.Base64d(str))
		return map[string]string{}, err{base64d.Base64d(str) + " --> this link is not ss link!"}
	}
	return node, nil
}

func ssrRe(str string) (map[string]string, error) {
	ssrRe, _ := regexp.Compile("(.*):([0-9]*):(.*):(.*):(.*):(.*)/?obfsparam=(.*)&protoparam=(.*)&remarks=(.*)&group=(.*)")
	node := map[string]string{}
	ssr := ssrRe.FindAllStringSubmatch(base64d.Base64d(str), -1)
	if len(ssr) != 0 {
		node["template"] = "ssr"
		node["server"] = ssr[0][1]
		node["serverPort"] = ssr[0][2]
		node["protocol"] = ssr[0][3]
		node["method"] = ssr[0][4]
		node["obfs"] = ssr[0][5]
		node["password"] = base64d.Base64d(ssr[0][6])
		node["obfsparam"] = base64d.Base64d(ssr[0][7])
		node["protoparam"] = base64d.Base64d(ssr[0][8])
		node["remarks"] = base64d.Base64d(ssr[0][9])
	} else {
		// log.Println("this link is not ssr link!", base64d.Base64d(str))
		return map[string]string{}, err{base64d.Base64d(str) + " --> this link is not ssr link!"}
	}
	return node, nil
}

// GetNode 获取节点信息
func GetNode(link string) (map[string]string, error) {
	re, _ := regexp.Compile("(.*)://(.*)")
	ssOrSsr := re.FindAllStringSubmatch(link, -1)
	var node map[string]string
	switch ssOrSsr[0][1] {
	case "ss":
		ss, err := ssRe(ssOrSsr[0][2])
		if err != nil {
			return map[string]string{}, err
		}
		node = ss
	case "ssr":
		ssr, err := ssrRe(ssOrSsr[0][2])
		if err != nil {
			return map[string]string{}, err
		}
		node = ssr
	}
	return node, nil
}

func main() {
	ss := "ssr://YWVzLTI1Ni1jZmI6NmFLZDVvR3A2THFyQDEuMS4xLjE6NTM"
	ssr := "ss://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz02YUtkNW9HcDZMcXImZ3JvdXA9NmFLZDVvR3A2THFy"
	fmt.Println(GetNode(ss))
	fmt.Println(GetNode(ssr))
}
