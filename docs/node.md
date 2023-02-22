# node json config

```json
{
   // maybe deprecated in future, move to bbolt cache
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
   // maybe deprecated in future, move to bbolt cache
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
