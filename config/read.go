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
type Node struct{
	Server,Server_port,Protocol,Method,Obfs,Password,Obfsparam,Protoparam string
}

type Argument struct{
    Pid_file,Log_file,Workers string
    Python_path,Config_path,Ssr_path,Acl string
    Local_port,Local_address string
    Connect_verbose_info,Deamon,Fast_open string
}

type Ssr_config struct {
    Node Node
    Argument Argument
    /*
    Server,Server_port,Protocol,Method,Obfs,Password,Obfsparam,Protoparam,Local_port,Local_address string
    Pid_file,Log_file,Workers string
    Python_path,Config_path,Ssr_path,Acl string
    //,remarks string
    Connect_verbose_info,Deamon,Fast_open string
    */
}


func Read_config_db(db_path string)(Node,error){
    node := Node{}
    db,err := sql.Open("sqlite3",db_path)
    if err!=nil{
        fmt.Println(err)
        return node,err
    }
    defer db.Close()

    err = db.QueryRow("SELECT server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_present_node").
    Scan(&node.Server,&node.Server_port,&node.Protocol,&node.Method,&node.Obfs,&node.Password,&node.Obfsparam,&node.Protoparam)
    if err == sql.ErrNoRows {
        log.Println("请先选择一个节点,目前没有已选择节点\n")
		return node,err
    }

    node.Server = "-s "+node.Server+" "
    node.Server_port = "-p " +node.Server_port+" "
    if node.Protocol!=""{
        node.Protocol = "-O "+node.Protocol+" "
    }
    node.Method = "-m "+node.Method+" "
    if node.Obfs!=""{
        node.Obfs = "-o "+node.Obfs+" "
    }
    node.Password = "-k "+node.Password+" "
    if node.Obfsparam!=""{
        node.Obfsparam = "-g "+node.Obfsparam+" "
    }
    if node.Protoparam!=""{
        node.Protoparam = "-G "+node.Protoparam+" "
    }

	return node,nil
}


func Read_config_file(config_path string)Argument{
    argument := Argument{}
    argument.Pid_file = "--pid-file "+config_path+"/shadowsocksr.pid "
    argument.Log_file = "--log-file "+"/dev/null "
    argument.Workers = "--workers "+"1 "
    argument.Python_path = "/usr/bin/python3 "
    //argument.ssr_config_path = os.Getenv("HOME")+"/.config/SSRSub/ssr_config.conf"

	config_temp,err := ioutil.ReadFile(config_path + "/ssr_config.conf")
    if err != nil {
        fmt.Println(err)
    }
    
    re,_ := regexp.Compile("#.*$")
    for _,config_temp2 := range strings.Split(string(config_temp),"\n"){
        config_temp2 := strings.Split(re.ReplaceAllString(config_temp2,"")," ")
        switch config_temp2[0]{
        case "python_path":argument.Python_path = config_temp2[1]+" "
        case "ssr_path":argument.Ssr_path = config_temp2[1]+" "
        case "config_path":argument.Config_path = config_temp2[1]
        case "connect-verbose-info":argument.Connect_verbose_info = "--connect-verbose-info "
        case "workers":argument.Workers = "--workers "+config_temp2[1]+" "
        case "fast-open":argument.Fast_open = "--fast-open "
        case "pid-file":argument.Pid_file = "--pid-file "+config_temp2[1]+" "
        case "log-file":argument.Log_file = "--log-file "+config_temp2[1]+" "
        case "local_address":argument.Local_address = "-b "+config_temp2[1]+" "
        case "local_port":argument.Local_port = "-l "+config_temp2[1]+" "
        case "acl":argument.Acl = "--acl "+config_temp2[1]+" "
        case "deamon": argument.Deamon = "-d start"
        }
    }
	return argument
}


//读取配置文件
func Read_config(config_path,db_path string)Ssr_config{
    node,_ := Read_config_db(db_path)
    argument := Read_config_file(config_path)
    /*
    
        node.Server,node.Server_port,node.Protocol,node.Method,node.Obfs,node.Password,node.Obfsparam,node.Protoparam,argument.Local_port,argument.Local_address,
        argument.Pid_file,argument.Log_file,argument.Workers,
        argument.Python_path,argument.Config_path,argument.Ssr_path,argument.Acl,
        argument.Connect_verbose_info,argument.Deamon,argument.Fast_open}
    */
    return Ssr_config{node,argument}
}