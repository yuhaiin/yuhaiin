package subscription

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"

	"../config"
)

// GetLink 读取订阅链接(数据库)
func GetLink(sqlPath string) []string {
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT link FROM subscription_link;")
	if err != nil {
		fmt.Println(err)
	}

	var subscriptionLink []string
	for rows.Next() {
		var link string
		rows.Scan(&link)
		subscriptionLink = append(subscriptionLink, link)
	}
	return subscriptionLink
}

// AddLink 添加订阅链接
func AddLink(link, sqlPath string) {
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()
	db.Exec("INSERT INTO subscription_link(link)values(?)", link)
}

// LinkDelete 删除订阅链接(数据库)
func LinkDelete(sqlPath string) {
	var links []string
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()

	err = db.QueryRow("SELECT link FROM subscription_link").Scan(err)
	if err == sql.ErrNoRows {
		log.Println("there is no link to delete!")
		return
	}
	rows, err := db.Query("SELECT link FROM subscription_link")
	var link string
	for rows.Next() {
		err = rows.Scan(&link)
		links = append(links, link)
	}
	//fmt.Println(subscription_link)
	for num, linkTemp := range links {
		fmt.Println(strconv.Itoa(num+1) + "." + linkTemp)
	}
	fmt.Print(config.GetFunctionString()["returnMenu"] + ">>>")

	var selectDelete int
	fmt.Scanln(&selectDelete)

	switch {
	case selectDelete == 0:
		return
	case selectDelete >= 1 && selectDelete <= len(links):
		db.Exec("DELETE FROM subscription_link WHERE link = ?", links[selectDelete-1])
	default:
		fmt.Println("enter error,please retry.")
		LinkDelete(sqlPath)
		return
	}
}
