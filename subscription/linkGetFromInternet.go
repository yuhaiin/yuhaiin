package subscription

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"../base64d"
)

func getOneLinkBodyByHTTP(url string) string {
	res, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
		fmt.Println("网络出错!")
		return ""
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		fmt.Println("可能出错原因,请检查能否成功访问订阅连接.")
	}
	return string(body)
	//ioutil.WriteFile(read_config().config_path,[]byte(body),0644)
}

func strBase64d(str []string, db *sql.DB) {
	for i, str := range str {
		if str == "" {
			continue
		}
		node, err := GetNode(str)
		if err != nil {
			log.Println(err)
			continue
		}
		db.Exec("INSERT INTO SSR_info(id,remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)values(?,?,?,?,?,?,?,?,?,?)", i+1, node["remarks"], node["server"], node["serverPort"], node["protocol"], node["method"], node["obfs"], node["password"], node["obfsparam"], node["protoparam"])
	}
}

// AddAllNodeFromLink 添加所有订阅的所有节点(sqlite数据库)
func AddAllNodeFromLink(sqlPath string) {

	//访问数据库
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}

	defer db.Close()

	var strB string
	for _, linkTemp := range GetLink(sqlPath) {
		//str_2 = append(str_2,base64d.Base64d(http_get_subscription(subscription_link_temp))...)
		strB += base64d.Base64d(getOneLinkBodyByHTTP(linkTemp))
	}
	db.Exec("BEGIN TRANSACTION;")
	strBase64d(strings.Split(strB, "\n"), db)
	db.Exec("COMMIT;")
}
