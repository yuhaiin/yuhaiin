package subscription

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

func Get_db(sql_path string) *sql.DB {
	db, err := sql.Open("sqlite3", sql_path)
	if err != nil {
		fmt.Println(err)
		return db
	}
	return db
}

//删除所有的节点
func Delete_config_db(sql_path string) {
	//访问数据库
	db := Get_db(sql_path)

	defer db.Close()

	//清空表
	db.Exec("DELETE FROM SSR_info;")
}
