cd /home/asutorufa/program/shadowsocksr-python/init
pro='/home/asutorufa/program/shadowsocksr-python/shadowsocks'
before_pro=`pwd`
update_configs(){
    echo 'update configs'
}
start_demon(){
    configs_number=`jq '.configs|length' gui-config.json`;
    for((i=0;i<configs_number;i++))
    do
        echo $i','`jq '.configs['$i'].remarks' gui-config.json`;
    done
    echo '请输入想要使用的序号'
    read i
    server=`jq -r '.configs['$i'].server' gui-config.json`
    server_port=`jq -r '.configs['$i'].server_port' gui-config.json`
    method=`jq -r '.configs['$i'].method' gui-config.json`
    obfs=`jq -r '.configs['$i'].obfs' gui-config.json`
    obfsparam=`jq -r '.configs['$i'].obfsparam' gui-config.json`
    password=`jq -r '.configs['$i'].password' gui-config.json`
    protocol=`jq -r '.configs['$i'].protocol' gui-config.json`
    protoparam=`jq -r '.configs['$i'].protoparam' gui-config.json`
    cd $pro
    sudo python local.py -s $server -p $server_port -k $password -m $method \
    -o $obfs -O $protocol -G $protoparam -g $obfsparam -d start
    cd $before_pro
}
stop_demon(){
    echo 'stop demon'
    cd $pro
    sudo python local.py -d stop
    cd $before_pro
}
while true
do
    #echo 'select one'
    echo '1.update configs'
    echo '2.start ssr demon'
    echo '3.stop ssr demon'
    echo '4.close this window'
    read select

    if [ $select -eq 1 ]
    then
        update_configs
    elif [ $select -eq 2 ]
    then
        start_demon
    elif [ $select -eq 3 ]
    then
        stop_demon
    elif [ $select -eq 4 ]
    then
        exit
    else 
        echo 'error'
    fi
done
