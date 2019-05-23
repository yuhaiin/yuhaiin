package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	router := gin.Default()
	router.LoadHTMLGlob("./**")
	router.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title":          "SSRSub",
			"server_remarks": List_list_db(),
		})
	})

	router.POST("/submit", func(c *gin.Context) {
		id, _ := c.GetPostForm("server")
		node := getOneNodeAll(id)
		c.HTML(200, "server.html", gin.H{
			"id":      node["id"],
			"remarks": node["remarks"],
			"server":  node["server"],
		})
		// c.String(200, getOneNodeAll(id)["remarks"])
	})
	router.Run(":8081")
}

func getOneNodeAll(id string) map[string]string {
	db, err := sql.Open("sqlite3", "/home/asutorufa/.config/SSRSub/SSR_config.db")
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
	db, err := sql.Open("sqlite3", "/home/asutorufa/.config/SSRSub/SSR_config.db")
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
