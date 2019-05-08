package subscription

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"sync"
)

//读取订阅链接(数据库)
func Get_subscription_link(sql_path string) []string {
	db := Get_db(sql_path)
	defer db.Close()
	rows, err := db.Query("SELECT link FROM subscription_link;")
	if err != nil {
		fmt.Println(err)
	}

	var subscription_link []string
	for rows.Next() {
		var link string
		rows.Scan(&link)
		subscription_link = append(subscription_link, link)
	}
	return subscription_link
}

//初始化订阅连接数据库
func Subscription_link_init(sql_path string, wg *sync.WaitGroup) {
	db := Get_db(sql_path)
	//关闭数据库
	defer db.Close()
	//创建表
	db.Exec("CREATE TABLE IF NOT EXISTS subscription_link(link TEXT);")

	wg.Done()
}

//添加订阅链接
func Subscription_link_add(subscription_link, sql_path string) {
	db := Get_db(sql_path)
	defer db.Close()
	db.Exec("INSERT INTO subscription_link(link)values(?)", subscription_link)
}

//删除订阅链接(数据库)
func Subscription_link_delete(sql_path string) {
	var subscription_link []string
	db := Get_db(sql_path)
	defer db.Close()

	var err error
	err = db.QueryRow("SELECT link FROM subscription_link").Scan(err)
	if err == sql.ErrNoRows {
		log.Println("没有已经添加的订阅链接")
		return
	}
	rows, err := db.Query("SELECT link FROM subscription_link")
	var link string
	for rows.Next() {
		err = rows.Scan(&link)
		subscription_link = append(subscription_link, link)
	}
	//fmt.Println(subscription_link)
	for num, link_temp := range subscription_link {
		fmt.Println(strconv.Itoa(num+1) + "." + link_temp)
	}
	fmt.Print("\n输入0返回菜单>>>")

	var select_delete int
	fmt.Scanln(&select_delete)

	switch {
	case select_delete == 0:
		return
	case select_delete >= 1 && select_delete <= len(subscription_link):
		db.Exec("DELETE FROM subscription_link WHERE link = ?", subscription_link[select_delete-1])
	default:
		fmt.Println("enter error,please retry.")
		Subscription_link_delete(sql_path)
		return
	}
}
