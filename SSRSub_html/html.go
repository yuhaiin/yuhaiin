package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	getdelay "../net"
	ssr_process "../process"
	"../subscription"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

var configPath = os.Getenv("HOME") + "/.config/SSRSub"
var sqlPath = configPath + "/SSR_config.db"

func main() {
	router := gin.Default()
	router.LoadHTMLGlob("./**/**")
	router.GET("/", func(c *gin.Context) {
		_, ssrStatus := ssr_process.Get(configPath)
		c.HTML(200, "sidebar.html", gin.H{
			"now_node":       subscription.GetNowNode(sqlPath),
			"ssr_status":     ssrStatus,
			"title":          "SSRSub",
			"server_remarks": List_list_db(),
			"home":           true,
		})
	})

	router.POST("/submit", func(c *gin.Context) {
		id, _ := c.GetPostForm("server")
		subscription.SsrSQLChangeNode(id, sqlPath)
		_, ssrStatus := ssr_process.Get(configPath)
		if ssrStatus == true {
			ssr_process.Stop(configPath)
			ssr_process.Start(configPath, sqlPath)
		}
		node := getOneNodeAll(id)
		delay, _ := getdelay.Tcp_delay(node["server"], node["server_port"])
		c.HTML(200, "sidebar.html", gin.H{
			"id":          node["id"],
			"remarks":     node["remarks"],
			"server":      node["server"],
			"server_port": node["server_port"],
			"protocol":    node["protocol"],
			"method":      node["method"],
			"obfs":        node["obfs"],
			"password":    node["password"],
			"obfsparam":   node["obfsparam"],
			"protoparam":  node["protoparam"],
			"delay":       delay,
			"server_bool": true,
		})
		// c.String(200, getOneNodeAll(id)["remarks"])
	})

	router.GET("/link", func(c *gin.Context) {
		link := subscription.Get_subscription_link(sqlPath)
		c.HTML(200, "sidebar.html", gin.H{
			"subscription": true,
			"link":         link,
		})
	})

	router.Run(":8081")
}

func getOneNodeAll(id string) map[string]string {
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()
	var id_, remarks, server, server_port, protocol, method, obfs, password, obfsparam, protoparam string
	db.QueryRow("SELECT id,remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_info where id = ?", id).Scan(&id_, &remarks, &server, &server_port, &protocol, &method, &obfs, &password, &obfsparam, &protoparam)
	return map[string]string{
		"id":          id_,
		"remarks":     remarks,
		"server":      server,
		"server_port": server_port,
		"protocol":    protocol,
		"method":      method,
		"obfs":        obfs,
		"password":    password,
		"obfsparam":   obfsparam,
		"protoparam":  protoparam,
	}
}
func List_list_db() [][]string {
	//访问数据库
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()

	//查找
	rows, err := db.Query("SELECT id,remarks FROM SSR_info ORDER BY id ASC;")
	if err != nil {
		log.Println(err)
	}
	remarks_ := [][]string{}
	//var server,server_port,protocol,method,obfs,password,obfsparam,protoparam string
	var remarks, id string
	for rows.Next() {
		//err = rows.Scan(&server,&server_port,&protocol,&method,&obfs,&password,&obfsparam,&protoparam)
		err = rows.Scan(&id, &remarks)
		// fmt.Println(id + "." + remarks)
		remarks_ = append(remarks_, []string{id, remarks})
	}
	// fmt.Println(remarks_)
	return remarks_
}
