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

func http_get_subscription(url string) string {
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

//添加所有订阅的所有节点(sqlite数据库)
func Add_config_db(sql_path string) {

	//访问数据库
	db := Get_db(sql_path)

	defer db.Close()

	var str_2 string
	for _, subscription_link_temp := range Get_subscription_link(sql_path) {
		//str_2 = append(str_2,base64d.Base64d(http_get_subscription(subscription_link_temp))...)
		str_2 += base64d.Base64d(http_get_subscription(subscription_link_temp))
	}
	db.Exec("BEGIN TRANSACTION;")
	strBase64d(strings.Split(str_2, "\n"), db)
	db.Exec("COMMIT;")
}

//初始化节点列表
func Init_config_db(sql_path string) {

	//访问数据库
	db := Get_db(sql_path)
	defer db.Close()

	db.Exec("BEGIN TRANSACTION;")
	//创建表
	db.Exec(`
	CREATE TABLE IF NOT EXISTS SSR_info(
        id INTERGER,
        remarks TEXT,
        server TEXT,
        server_port TEXT,
        protocol TEXT,
        method TEXT,
        obfs TEXT,
        password TEXT,
        obfsparam TEXT,
        protoparam TEXT);
	`)

	//向表中插入none值
	//db.Exec("INSERT INTO SSR_info(id,remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)values(none,none,none,none,none,none,none,none,none,none)")

	db.Exec("COMMIT;")
}
