 package config

 import (
	 "fmt"
	 "database/sql"
	 "log"
	 "io/ioutil"
	 "strings"
	 "regexp"
	 _ "github.com/mattn/go-sqlite3"
 )
type node struct{
	server,server_port,protocol,method,obfs,password,obfsparam,protoparam string
}

type argument struct{
	pid_file,log_file,workers string
}


 func read_config_db(db_path string)(node,error){

    db,err := sql.Open("sqlite3",db_path)
    if err!=nil{
        fmt.Println(err)
    }
    defer db.Close()

    var server,server_port,protocol,method,obfs,password,obfsparam,protoparam string
    err = db.QueryRow("SELECT server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_present_node").Scan(&server,&server_port,&protocol,&method,&obfs,&password,&obfsparam,&protoparam)
    if err == sql.ErrNoRows {
        log.Println("请先选择一个节点,目前没有已选择节点\n")
		return node{},err
	}
	/*
	ssr_config.server = "-s "+server+" "
    ssr_config.server_port = "-p " +server_port+" "
    if protocol!=""{
        ssr_config.protocol = "-O "+protocol+" "
    }
    ssr_config.method = "-m "+method+" "
    if obfs!=""{
        ssr_config.obfs = "-o "+obfs+" "
    }
    ssr_config.password = "-k "+password+" "
    if obfsparam!=""{
        ssr_config.obfsparam = "-g "+obfsparam+" "
    }
    if protoparam!=""{
        ssr_config.protoparam = "-G "+protoparam+" "
	}
	*/
	return node{server,server_port,protocol,method,obfs,password,obfsparam,protoparam},nil
 }


 func read_config_file(config_path string)argument{
	config_temp,err := ioutil.ReadFile(config_path + "/ssr_config.conf")
    if err != nil {
        fmt.Println(err)
	}
	lines := strings.Split(string(config_temp),"\n")
    re3,_ := regexp.Compile("#.*$")
    for _,config_temp2 := range lines{
        config_temp2 = re3.ReplaceAllString(config_temp2,"")
		config_temp2 := strings.Split(config_temp2," ")
		fmt.Println(config_temp2)
	}
	return argument{}
 }

 /*
//读取配置文件
func read_config_db(config_path,db_path string)ssr_config{

    ssr_config := ssr_config_init(config_path)
    //var log_file,pid_file,fast_open,workers,connect_verbose_info,ssr_path,python_path,config_path,config_url string
    config_temp,err := ioutil.ReadFile(ssr_config_path)
    if err != nil {
        fmt.Println(err)
    }
    lines := strings.Split(string(config_temp),"\n")
    re3,_ := regexp.Compile("#.*$")
    for _,config_temp2 := range lines{
        config_temp2 = re3.ReplaceAllString(config_temp2,"")
        config_temp2 := strings.Split(config_temp2," ")
        if config_temp2[0] == "python_path"{
            ssr_config.python_path = config_temp2[1]+" "
        } else if config_temp2[0] == "ssr_path"{
            ssr_config.ssr_path = config_temp2[1]+" "
        }else if config_temp2[0] == "config_path"{
            ssr_config.config_path = config_temp2[1]
        }else if config_temp2[0] == "connect-verbose-info"{
            ssr_config.connect_verbose_info = "--connect-verbose-info "
        }else if config_temp2[0] == "workers"{
            ssr_config.workers = "--workers "+config_temp2[1]+" "
        }else if config_temp2[0] == "fast-open"{
            ssr_config.fast_open = "--fast-open "
        }else if config_temp2[0] == "pid-file"{
            ssr_config.pid_file = "--pid-file "+config_temp2[1]+" "
        }else if config_temp2[0] == "log-file"{
            ssr_config.log_file = "--log-file "+config_temp2[1]+" "
        }else if config_temp2[0] == "local_address"{
            ssr_config.local_address = "-b "+config_temp2[1]+" "
        }else if config_temp2[0] == "local_port"{
            ssr_config.local_port = "-l "+config_temp2[1]+" "
        }else if config_temp2[0] == "acl"{
            ssr_config.acl = "--acl "+config_temp2[1]+" "
        }else if config_temp2[0] == "deamon"{
            ssr_config.deamon = "-d start"
        }
	}
}
*/