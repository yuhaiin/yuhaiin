# node json config

## Per-node latency target

Each node can override the global HTTP target used by its TCP Ping check. The
request is sent through that node's outbound chain, so a node can use an
intranet health endpoint that is reachable only through its tunnel. Leave the
URL empty or omit `latency` to keep using the global target configured under
Web UI **Latency Targets**.

```json
{
  "latency": {
    "url": "https://intranet.example.com/health",
    "insecure_skip_verify": false
  }
}
```

Only absolute `http://` and `https://` URLs are accepted. TLS certificate and
hostname verification stay enabled by default. Set `insecure_skip_verify` to
`true` only for an HTTPS endpoint whose certificate cannot be trusted. This
setting applies to this node's HTTP/TCP latency check; UDP, DNS, IP, and STUN
checks continue to use their global targets.

```json
{
   "tcp":{ // global tcp using node, copy from nodes while changing
      "hash":"606f65",
      "name":"default",
      "group":"default",
      "origin":"manual",
      "protocols":[
         {
            "direct":{}
         }
      ]
   },
   "udp":{// global udp using node, copy from nodes while changing
      "hash":"606f65",
      "name":"default",
      "group":"default",
      "origin":"manual",
      "protocols":[
         {
            "direct":{}
         }
      ]
   },


   "manager":{
      "group_nodes_map":{ // group-node:node-hash mapping
         "default":{ // group name
            "node_hash_map":{
               "default":"606f65", // node-name:node-hash map
               "warp":"eb7653"
            }
         }
      },


      "nodes":{// all nodes
         "606f65":{ // node hash
            "hash":"606f65",
            "name":"default",
            "group":"default",
            "origin":"manual",
            "protocols":[
               {
                  "direct":{}
               }
            ]
         },
         "eb7653":{
            "hash":"eb7653",
            "name":"warp",
            "group":"default",
            "origin":"manual",
            "protocols":[
               {
                  "simple":{
                     "host":"127.0.0.1",
                     "port":40000,
                     "packet_conn_direct":true
                  }
               },
               {
                  "socks5":{
                     "hostname":"127.0.0.1"
                  }
               }
            ]
         }
      },


      "tags":{ // tags config

         "warp":{ // tag name
            "tag":"warp",
            "hash":[ // specify node/tag for current tag
               "eb7653"
            ]
         },

         
         "fast": {
            "tag": "fast",
            "hash": [
                "warp", // another tag name, can't set to self
                "606f65" // node hash
            ]
         }
      }
   }
}
```
