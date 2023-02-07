# slpscan - protecting the innocent

## intro

This is a research tool, created for looking deeper into SLP at the internet.
Due current events we decided to publish a version of it, to support defenders and researchers tackle the current ESXi exploitation scheme.

## usage
Show all supported functions  
```
./slpscan.py -m ?
----------------------------------------------------------------------
SLPv1 Modes                    Operation       Description
----------------------------------------------------------------------
svc_req_v1                     1
svc_reply_v1                   2
svc_attr_req_v1                6
svc_attr_reply_v1              7
svc_type_req_v1                9
svc_type_reply_v1              10
----------------------------------------------------------------------
SLPv2 Modes                    Operation       Description
----------------------------------------------------------------------
svc_req_v2                     1
svc_reply_v2                   2
svc_attr_req_v2                6
svc_attr_reply_v2              7
svc_type_req_v2                9
svc_type_reply_v2              10
```

Do slp svc req v2   
`./slpscan.py -l 192.168.170.50 -m svc_req_v2`

Do slp svc type req v1  
`./slpscan.py -l 192.168.170.50 -m svc_type_req_v1`


Do slp attribute req for vmware v2
`./slpscan.py -l 192.168.170.50 -m svc_attr_req_v2`

Show supported probes
```
./slpscan.py -P?

SLP Request               | Brief                              | Devices      
-------------------------------------------------------------------------------
svc_type_req_holder_v1    | example pkt, svc_type_req_v1       |              
svc_attr_req_holder_v1    | example request, svc_attr_req_v1   |              
svc_req_holder_v2         | example pkt, svc_req_v2            |              
svc_type_req_holder_v2    | example pkt, svc_type_req_v2       |              
svc_attr_req_holder_v2    | example pkt, svc_attr_req_v2       |              
VMWARE_SVC_Request_https  | service:https                      |          

```

For SLP identification against ESXi Hosts use the probe published within the release:  

```
./slpscan.py -l <ip> -P VMWARE_SVC_Request_https
```

If you have a datacenter and need to check a big list of hosts use the -L option. 

If you have a specific probe you can easily add it to the probe json file in the libs directory. There are already several examples to do so.

General help:

```
usage: slpscan.py [-h] [-l HOST] [-L HOSTLIST] [-p PORT] [-t THRCNT] [-m SLP_MODE]
                     [-P PROBE_MODE] [-d PKT_DELAY] [-T TIMEOUT] [-o OUTFILE] [-oj OUTFILE_JSON]
                     [-r UNRANDOM] [-R RANDOMIP]

service location protocol 0.3.7 by dash in published 2023

options:
  -h, --help            show this help message and exit
  -l HOST, --host HOST  host to check version
  -L HOSTLIST, --hostlist HOSTLIST
                        hostlist to check
  -p PORT, --port PORT  slp port (default:427)
  -t THRCNT, --threads THRCNT
                        how many threads
  -m SLP_MODE, --slp-mode SLP_MODE
                        what attack mode to choose, ? for list
  -P PROBE_MODE, --probe-mode PROBE_MODE
                        what probe to send, ? for list
  -d PKT_DELAY, --packet-delay PKT_DELAY
                        set the delay(in seconds) a packet is sent, delay is per thread (1s and
                        10 threads, each second 10 threads are working)
  -T TIMEOUT, --timeout TIMEOUT
                        timeout of socket recv
  -o OUTFILE, --outfile OUTFILE
                        outfile in txt format
  -oj OUTFILE_JSON, --outfile-json OUTFILE_JSON
                        outfile in json format
  -r UNRANDOM, --unrandom UNRANDOM
                        disable random targetlist
  -R RANDOMIP, --randomIP RANDOMIP
                        generate random ips on the fly
```

# outro

This tool is part of an ongoing research conducted by Marco Lux (ping@curesec.com) and Pedro Umbelino (pedro.umbelino@bitsight.com). 
