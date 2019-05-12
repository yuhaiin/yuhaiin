package config

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"runtime"
	"strings"

	"../subscription"
)

type Ssr_config struct {
	Node     map[string]string
	Argument map[string]string
}

func Read_config_db(db_path string) (map[string]string, error) {
	node := map[string]string{}
	//node := Node{}
	db := subscription.Get_db(db_path)
	defer db.Close()

	var Server, Server_port, Protocol, Method, Obfs, Password, Obfsparam, Protoparam string
	err := db.QueryRow("SELECT server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_present_node").
		//Scan(node["Server"],node["Server_port"],node["Protocol"],node["Method"],node["Obfs"],node["Password"],node["Obfsparam"],node["Protoparam"])
		Scan(&Server, &Server_port, &Protocol, &Method, &Obfs, &Password, &Obfsparam, &Protoparam)

	if err == sql.ErrNoRows {
		log.Println("请先选择一个节点,目前没有已选择节点\n")
		return node, err
	}

	node["Server"] = "-s " + Server + " "
	node["Server_port"] = "-p " + Server_port + " "
	if Protocol != "" {
		node["Protocol"] = "-O " + Protocol + " "
	}
	node["Method"] = "-m " + Method + " "
	if Obfs != "" {
		node["Obfs"] = "-o " + Obfs + " "
	}
	node["Password"] = "-k " + Password + " "
	if Obfsparam != "" {
		node["Obfsparam"] = "-g " + Obfsparam + " "
	}
	if Protoparam != "" {
		node["Protoparam"] = "-G " + Protoparam + " "
	}

	return node, nil
}

func conifg_file_init(config_path string) map[string]string {
	argument := map[string]string{}
	argument["Pid_file"] = "--pid-file " + config_path + "/shadowsocksr.pid "
	argument["Log_file"] = "--log-file " + "/dev/null "

	// if argument["Workers"] == "" {
	// 	argument["Workers"] = "--workers " + "1 "
	// }

	argument["Python_path"] = Get_python_path() + " "
	if runtime.GOOS == "windows" {
		argument["Ssr_path"] = config_path + `\shadowsocksr\shadowsocks/local.py `
	} else {
		argument["Ssr_path"] = config_path + "/shadowsocksr/shadowsocks/local.py "
	}
	argument["Local_address"] = "-b 127.0.0.1 "
	argument["Local_port"] = "-l 1080 "
	return argument
}

func Read_config_file(config_path string) map[string]string {
	argument := conifg_file_init(config_path)

	config_temp, err := ioutil.ReadFile(config_path + "/ssr_config.conf")
	if err != nil {
		fmt.Println(err)
	}

	in_line := "\n"
	if runtime.GOOS == "windows" {
		in_line = "\r\n"
	}

	re, _ := regexp.Compile("#.*$")
	for _, config_temp2 := range strings.Split(string(config_temp), in_line) {
		config_temp2 := strings.Split(re.ReplaceAllString(config_temp2, ""), " ")
		switch config_temp2[0] {
		case "python_path":
			argument["Python_path"] = config_temp2[1] + " "
		case "-python_path":
			argument["Python_path"] = ""
		case "ssr_path":
			argument["Ssr_path"] = config_temp2[1] + " "
		case "-ssr_path":
			argument["Ssr_path"] = ""
		case "config_path":
			argument["Config_path"] = config_temp2[1]
		case "connect-verbose-info":
			argument["Connect_verbose_info"] = "--connect-verbose-info "
		case "workers":
			argument["Workers"] = "--workers " + config_temp2[1] + " "
		case "fast-open":
			argument["Fast_open"] = "--fast-open "
		case "pid-file":
			argument["Pid_file"] = "--pid-file " + config_temp2[1] + " "
		case "-pid-file":
			argument["Pid_file"] = ""
		case "log-file":
			argument["Log_file"] = "--log-file " + config_temp2[1] + " "
		case "-log-file":
			argument["Log_file"] = ""
		case "local_address":
			argument["Local_address"] = "-b " + config_temp2[1] + " "
		case "local_port":
			argument["Local_port"] = "-l " + config_temp2[1] + " "
		case "acl":
			argument["Acl"] = "--acl " + config_temp2[1] + " "
		case "timeout":
			argument["Timeout"] = "-t " + config_temp2[1] + " "
		case "deamon":
			argument["Deamon"] = "-d start"
		}
	}
	return argument
}

//读取配置文件
func Read_config(config_path, db_path string) Ssr_config {
	node, _ := Read_config_db(db_path)
	argument := Read_config_file(config_path)
	return Ssr_config{node, argument}
}
