package subscription

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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
