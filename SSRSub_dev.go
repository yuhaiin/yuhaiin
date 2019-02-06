package main

import "fmt"
import "encoding/base64"
import "net/http"
import "io/ioutil"
import "strings"
import "bufio"

var config_middle_temp[] string
var config_path = "/home/.cache/SSRSub/config.txt"
var config_url = "" //订阅链接

func base64d(str string)string{
    for i:=0;i<=4-len(str)%4;i++{
        str+="="
    }
    de_str,_ := base64.URLEncoding.DecodeString(str)
    return string(de_str)
}

func read_config(config_path string)string{
    config_temp,err := ioutil.ReadFile(config_path)
    if err != nil {
        fmt.Println(err)
    }
    return string(config_temp)
}

func update_config(config_path,url string){
    res,_ := http.Get(config_url)
    body,_ := ioutil.ReadAll(res.Body)
    ioutil.WriteFile(config_path,[]byte(body),0644)
}

func str_replace(str string)[]string{
    var config[] string
    scanner := bufio.NewScanner(strings.NewReader(strings.Replace(base64d(str),"ssr://","",-1)))

for scanner.Scan() {
    str_temp := strings.Replace(base64d(scanner.Text()),"/?obfsparam=",":",-1)
    str_temp = strings.Replace(str_temp,"&protoparam=",":",-1)
    str_temp = strings.Replace(str_temp,"&remarks=",":",-1)
    str_temp = strings.Replace(str_temp,"&group=",":",-1)
    config = append(config,str_temp)
}
return config
}

func list_list(config_array []string){
    for num,config_temp := range config_array{
        config_temp2 := strings.Split(config_temp,":")
        fmt.Println(num+1,base64d(config_temp2[len(config_temp2)-2]))
    }
}

func ssr_start(n int){
    config_split := strings.Split(config_middle_temp[n-1],":")
    var server string
    if len(config_split) == 17 {
        server = config_split[0]+":"+config_split[1]+":"+config_split[2]+":"+config_split[3]+":"+config_split[4]+":"+config_split[5]+":"+config_split[6]+":"+config_split[7]
    } else if len(config_split) == 10 {
        server = config_split[0]
    }
    server_port := config_split[len(config_split)-9]
    protocol := config_split[len(config_split)-8]
    method := config_split[len(config_split)-7]
    obfs := config_split[len(config_split)-6]
    password := base64d(config_split[len(config_split)-5])
    obfsparam := base64d(config_split[len(config_split)-4])
    protoparam := base64d(config_split[len(config_split)-3])
    remarks := base64d(config_split[len(config_split)-2])
    fmt.Println(server,server_port,protocol,method,obfs,password,obfsparam,protoparam,remarks)
}

func menu()int{
    var n int
    fmt.Scanln(&n)
    return n
}
func main(){
    a := string(read_config(config_path))
    config_middle_temp = str_replace(a)
    list_list(config_middle_temp)
    ssr_start(menu())
}
