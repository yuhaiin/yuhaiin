package subscription

import (
	"database/sql"
	"fmt"
	"log"
	// _ "github.com/mattn/go-sqlite3"
)

// GetAllNodeRemarksAndID  like name
func GetAllNodeRemarksAndID(sqlPath string) [][]string {
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

// SsrSQLChangeNode change now node
func SsrSQLChangeNode(id, sqlPath string) {
	db := Get_db(sqlPath)
	defer db.Close()
	db.Exec("BEGIN TRANSACTION;")
	db.Exec("DELETE FROM SSR_present_node")
	db.Exec("INSERT INTO SSR_present_node(remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam) SELECT remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_info WHERE id = ?", id)
	db.Exec("COMMIT;")
}

// GetNowNode like name
func GetNowNode(sqlPath string) string {
	db := Get_db(sqlPath)
	defer db.Close()
	var remarks string
	if err := db.QueryRow("SELECT remarks FROM SSR_present_node;").Scan(&remarks); err == sql.ErrNoRows {
		log.Println("节点列表为空,请先更新订阅")
		return ""
	}
	return remarks
}

// GetOneNodeAll like name
func GetOneNodeAll(id, sqlPath string) map[string]string {
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
