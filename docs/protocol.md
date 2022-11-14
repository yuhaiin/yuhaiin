# protocols

can generate protocols template at web page `GEOUP -> Add New Node`  
protocol is stratification model, that will process data by protocols order  

for example socks5 client  

wee need a outbound protocol or dialer(tcp,udp dialer), such as simple(simple write data to host:port or with tls)

```json
{
 "simple": {
  "host": "127.0.0.1",
  "port": 1080,
  "packet_conn_direct": true, // udp data write to host:port or origin address
  "tls_config": {
   "enable": false,
   "server_name": "",
   "ca_cert": [
    "AAE="
   ],
   "insecure_skip_verify": false,
   "next_protos": []
  }
 }
}
```

socks5 protocol, that will wrap or unwrap with sock5 protocol

```json
{
 "socks5": {
  "hostname": "127.0.0.1",
  "user": "",
  "password": ""
 }
}
```

so a complete protocols config is

```json
{
 "hash": "",
 "name": "new node",
 "group": "template group",
 "origin": "manual",
 "protocols": [ // <-----------
  {
   "simple": {
    "host": "127.0.0.1",
    "port": 1080,
    "packet_conn_direct": false,
    "tls_config": {
     "enable": false,
     "server_name": "",
     "ca_cert": [],
     "insecure_skip_verify": false,
     "next_protos": []
    }
   }
  },
  {
   "socks5": {
    "hostname": "127.0.0.1",
    "user": "",
    "password": ""
   }
  }
 ]
}
```

another example that vmess protocol with websocket

```json
{
 "hash": "",
 "name": "new node",
 "group": "template group",
 "origin": "manual",
 "protocols": [
  {
   "simple": { // outbound/dialer
    "host": "example.com",
    "port": 50051,
    "packet_conn_direct": false
   }
  },
  {
   "websocket": { // websocket protocol
    "host": "websocket.example.com",
    "path": "/query",
    "tls": {
     "enable": true,
     "server_name": "websocket.example.com",
     "ca_cert": [],
     "insecure_skip_verify": false,
     "next_protos": []
    }
   }
  },
  {
   "vmess": { // vmess protocol
    "id": "e014f7ea-3350-4141-9b2c-0cc1b4fd8c22",
    "aid": "0",
    "security": "auto"
   }
  }
 ]
}
```
