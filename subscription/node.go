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
	remarksB := [][]string{}
	//var server,server_port,protocol,method,obfs,password,obfsparam,protoparam string
	var remarks, id string
	for rows.Next() {
		//err = rows.Scan(&server,&server_port,&protocol,&method,&obfs,&password,&obfsparam,&protoparam)
		err = rows.Scan(&id, &remarks)
		// fmt.Println(id + "." + remarks)
		remarksB = append(remarksB, []string{id, remarks})
	}
	// fmt.Println(remarks_)
	return remarksB
}

// SsrSQLChangeNode change now node
func SsrSQLChangeNode(id, sqlPath string) {
	db := Get_db(sqlPath)
	defer db.Close()
	db.Exec("BEGIN TRANSACTION;")
	db.Exec("DELETE FROM SSR_present_node")
	db.Exec("INSERT INTO SSR_present_node(remarks,server,server_port,protocol,"+
		"method,obfs,password,obfsparam,protoparam) SELECT remarks,server,server_port,"+
		"protocol,method,obfs,password,obfsparam,protoparam FROM SSR_info WHERE id = ?", id)
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

// GetNowNodeAll Get now node all information
func GetNowNodeAll(sqlPath string) (map[string]string, error) {
	node := map[string]string{}
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()

	var Server, ServerPort, Protocol, Method, Obfs, Password, Obfsparam, Protoparam string
	err = db.QueryRow("SELECT server,server_port,protocol,method,obfs,password,"+
		"obfsparam,protoparam FROM SSR_present_node").
		//Scan(node["Server"],node["Server_port"],node["Protocol"],node["Method"],node["Obfs"],node["Password"],node["Obfsparam"],node["Protoparam"])
		Scan(&Server, &ServerPort, &Protocol, &Method, &Obfs, &Password, &Obfsparam, &Protoparam)

	if err == sql.ErrNoRows {
		log.Println("请先选择一个节点,目前没有已选择节点")
		return node, err
	}
	node["server"] = Server
	node["serverPort"] = ServerPort
	node["protocol"] = Protocol
	node["method"] = Method
	node["obfs"] = Obfs
	node["password"] = Password
	node["obfsparam"] = Obfsparam
	node["protoparam"] = Protoparam

	return node, nil
}

// GetOneNodeAll like name
func GetOneNodeAll(id, sqlPath string) map[string]string {
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()
	var idB, remarks, server, serverPort, protocol, method, obfs, password, obfsparam, protoparam string
	db.QueryRow("SELECT id,remarks,server,server_port,protocol,method,obfs,"+
		"password,obfsparam,protoparam FROM SSR_info where id = ?", id).
		Scan(&idB, &remarks, &server, &serverPort, &protocol, &method, &obfs,
			&password, &obfsparam, &protoparam)
	return map[string]string{
		"id":          idB,
		"remarks":     remarks,
		"server":      server,
		"server_port": serverPort,
		"protocol":    protocol,
		"method":      method,
		"obfs":        obfs,
		"password":    password,
		"obfsparam":   obfsparam,
		"protoparam":  protoparam,
	}
}
