package subscription

import (
	"errors"
	"log"
	"net/url"
	"regexp"
	"strings"
)

func ssrRe(str string) (map[string]string, error) {
	// ssrRe, _ := regexp.Compile("(.*):([0-9]*):(.*):(.*):(.*):(.*)/?obfsparam=(.*)&protoparam=(.*)&remarks=(.*)&group=(.*)")
	ssrRe, _ := regexp.Compile("(.*):([0-9]*):(.*):(.*):(.*):(.*)(.*)")
	ssrReB, _ := regexp.Compile(".*/\\?(.*)")
	node := make(map[string]string)
	ssr := ssrRe.FindAllStringSubmatch(Base64d(str), -1)
	ssrB := ssrReB.FindAllStringSubmatch(Base64d(str), -1)

	//删除第一个元素
	if len(ssrB) > 0 {
		ssrC := strings.Split(ssrB[0][1], "&")
		for _, ssr := range ssrC {
			ssrA := strings.Split(ssr, "=")
			switch ssrA[0] {
			case "obfsparam":
				node["obfsparam"] = Base64d(ssrA[1])
			case "protoparam":
				node["protoparam"] = Base64d(ssrA[1])
			case "remarks":
				node["remarks"] = Base64d(ssrA[1])
			case "group":
				node["group"] = Base64d(ssrA[1])
			}
		}
	}
	// fmt.Println(node)
	if len(ssr) != 0 {
		node["template"] = "ssr"
		node["server"] = ssr[0][1]
		node["serverPort"] = ssr[0][2]
		node["protocol"] = ssr[0][3]
		node["method"] = ssr[0][4]
		node["obfs"] = ssr[0][5]
		node["password"] = Base64d(ssr[0][6])
		// node["obfsparam"] = base64d.Base64d(ssr[0][7])
		// node["protoparam"] = base64d.Base64d(ssr[0][8])
		// node["remarks"] = base64d.Base64d(ssr[0][9])
	} else {
		// log.Println("this link is not ssr link!", base64d.Base64d(str))
		return map[string]string{}, errors.New(Base64d(str) + " --> this link is not ssr link!")

	}
	return node, nil
}

// GetNode get decode node
func SsrParse(link string) (map[string]string, error) {
	re, _ := regexp.Compile("(.*)://(.*)")
	ssOrSsr := re.FindAllStringSubmatch(link, -1)
	if len(ssOrSsr) == 0 {
		return map[string]string{}, nil
	}
	log.Println(ssOrSsr[0][2])
	ssr, err := ssrRe(ssOrSsr[0][2])
	if err != nil {
		return map[string]string{}, err
	}
	node := ssr
	return node, nil
}

// Shadowsocksr node json struct
type Shadowsocksr struct {
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

func SsrParse2(link string) (*Shadowsocksr, error) {
	decodeStr := strings.Split(Base64d(strings.Replace(link, "ssr://", "", -1)), "/?")
	node := new(Shadowsocksr)
	x := strings.Split(decodeStr[0], ":")
	if len(x) != 6 {
		return node, errors.New(decodeStr[0] + " is not format link")
	}
	node.Server = x[0]
	node.ServerPort = x[1]
	node.Protocol = x[2]
	node.Method = x[3]
	node.Obfs = x[4]
	node.Password = Base64d(x[5])

	if len(decodeStr) > 1 {
		query, _ := url.ParseQuery(decodeStr[1])
		node.Group = Base64d(query.Get("group"))
		node.Obfsparam = Base64d(query.Get("obfsparam"))
		node.Protocol = Base64d(query.Get("protoparam"))
		node.Remarks = Base64d(query.Get("remarks"))
	}
	return node, nil
}
