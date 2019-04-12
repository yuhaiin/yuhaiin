package subscription

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	// _ "github.com/mattn/go-sqlite3"

	//"bufio"

	"regexp"
	"sync"

	//"time"
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

func str_bas64d(str []string, db *sql.DB) {
	re_first, _ := regexp.Compile("ssr*://(.*)")
	re, _ := regexp.Compile("(.*):([0-9]*):(.*):(.*):(.*):(.*)&obfsparam=(.*)&protoparam=(.*)&remarks=(.*)&group=(.*)")
	for i, str := range str {
		if str == "" {
			continue
		}

		config_split := re.FindAllStringSubmatch(strings.Replace(base64d.Base64d(re_first.FindAllStringSubmatch(str, -1)[0][1]), "/?", "&", -1), -1)[0]

		server := config_split[1]
		server_port := config_split[2]
		protocol := config_split[3]
		method := config_split[4]
		obfs := config_split[5]
		password := base64d.Base64d(config_split[6])
		obfsparam := base64d.Base64d(config_split[7])
		protoparam := base64d.Base64d(config_split[8])
		remarks := base64d.Base64d(config_split[9])
		//fmt.Println(num,remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)

		//向表中插入数据
		db.Exec("INSERT INTO SSR_info(id,remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)values(?,?,?,?,?,?,?,?,?,?)", i+1, remarks, server, server_port, protocol, method, obfs, password, obfsparam, protoparam)
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

	//temp := time.Now()

	db.Exec("BEGIN TRANSACTION;")
	str_bas64d(strings.Split(str_2, "\n"), db)
	db.Exec("COMMIT;")

	//deply := time.Since(temp)
	//fmt.Println(deply)
}

//初始化节点列表
func Init_config_db(sql_path string, wg *sync.WaitGroup) {

	//访问数据库
	db := Get_db(sql_path)
	defer db.Close()

	db.Exec("BEGIN TRANSACTION;")
	//创建表
	sql_table := `
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
        protoparam TEXT
    );
    `
	db.Exec(sql_table)

	//向表中插入none值
	//db.Exec("INSERT INTO SSR_info(id,remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)values(none,none,none,none,none,none,none,none,none,none)")

	db.Exec("COMMIT;")
	wg.Done()
}
