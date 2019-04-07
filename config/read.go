package config

import (
	"bytes"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type Ssr_config struct {
	Node     map[string]string
	Argument map[string]string
}

func Read_config_db(db_path string) (map[string]string, error) {
	node := map[string]string{}
	//node := Node{}
	db, err := sql.Open("sqlite3", db_path)
	if err != nil {
		fmt.Println(err)
		return node, err
	}
	defer db.Close()

	var Server, Server_port, Protocol, Method, Obfs, Password, Obfsparam, Protoparam string
	err = db.QueryRow("SELECT server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_present_node").
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

func Get_python_path() string {
	var out bytes.Buffer
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "where python")
		cmd.Stdin = strings.NewReader("some input")
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			log.Fatal(err)
			return ""
		}
		return strings.Replace(out.String(), "\r\n", "", -1)
		// return strings.Split(out.String(), ".exe")[0] + ".exe"
	} else {
		cmd := exec.Command("sh", "-c", "which python3")
		cmd.Stdin = strings.NewReader("some input")
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			cmd = exec.Command("sh", "-c", "which python")
			cmd.Stdout = &out
			err = cmd.Run()
			if err != nil {
				return ""
			}
		}
		return strings.Replace(out.String(), "\n", "", -1)
		// fmt.Printf("in all caps: %q", out.String())
		// fmt.Println(out.String())
	}
}

func Read_config_file(config_path string) map[string]string {
	argument := map[string]string{}

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
		case "ssr_path":
			argument["Ssr_path"] = config_temp2[1] + " "
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
		case "log-file":
			argument["Log_file"] = "--log-file " + config_temp2[1] + " "
		case "local_address":
			argument["Local_address"] = "-b " + config_temp2[1] + " "
		case "local_port":
			argument["Local_port"] = "-l " + config_temp2[1] + " "
		case "acl":
			argument["Acl"] = "--acl " + config_temp2[1] + " "
		case "deamon":
			argument["Deamon"] = "-d start"
		}
	}
	if argument["Pid_file"] == "" {
		argument["Pid_file"] = "--pid-file " + config_path + "/shadowsocksr.pid "
	}
	if argument["Log_file"] == "" {
		argument["Log_file"] = "--log-file " + "/dev/null "
	}

	// if argument["Workers"] == "" {
	// 	argument["Workers"] = "--workers " + "1 "
	// }

	if argument["Python_path"] == "" {
		argument["Python_path"] = Get_python_path() + " "
	}
	if argument["Ssr_path"] == "" {
		if runtime.GOOS == "windows" {
			argument["Ssr_path"] = config_path + `\shadowsocksr\shadowsocks/local.py `
		} else {
			argument["Ssr_path"] = config_path + "/shadowsocksr/shadowsocks/local.py "
		}
	}
	if argument["Local_address"] == "" {
		argument["Local_address"] = "-b 127.0.0.1 "
	}
	if argument["Local_port"] == "" {
		argument["Local_port"] = "-l 1080 "
	}
	return argument
}

//读取配置文件
func Read_config(config_path, db_path string) Ssr_config {
	node, _ := Read_config_db(db_path)
	argument := Read_config_file(config_path)
	return Ssr_config{node, argument}
}
