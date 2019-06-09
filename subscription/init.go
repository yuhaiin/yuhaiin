package subscription

import (
	"database/sql"
	"fmt"
)

// NowNodeInit init now node sql
func NowNodeInit(sqlPath string) {
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}
	//关闭数据库
	defer db.Close()

	//创建表
	db.Exec("BEGIN TRANSACTION;")
	db.Exec(`CREATE TABLE IF NOT EXISTS SSR_present_node(
        remarks TEXT,
        server TEXT,
        server_port TEXT,
        protocol TEXT,
        method TEXT,
        obfs TEXT,
        password TEXT,
        obfsparam TEXT,
		protoparam TEXT);`)
	//初始化插入空字符
	//db.Exec("INSERT INTO SSR_present_node(remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)values('none','none','none','none','none','none','none','none','none')")
	db.Exec("COMMIT;")
}

// LinkInit 初始化订阅连接数据库
func LinkInit(sqlPath string) {
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}
	//关闭数据库
	defer db.Close()
	//创建表
	db.Exec("CREATE TABLE IF NOT EXISTS subscription_link(link TEXT);")
}

// NodeInit 初始化节点列表
func NodeInit(sqlPath string) {

	//访问数据库
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}
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

// DeleteAllNode 删除所有的节点
func DeleteAllNode(sqlPath string) {
	//访问数据库
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}

	defer db.Close()

	//清空表
	db.Exec("DELETE FROM SSR_info;")
}
