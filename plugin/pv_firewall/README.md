# PV Firewall

DNS Firewall simple demo.

## Examples

~~~ 
corefile
.:53 {
    pv_firewall http://127.0.0.1:8000/policys/policy.json
    
    debug
    log
    errors
    forward . /etc/resolv.conf
}


policy.json
{
    "benign.net":{
        "all":"allow",
        "10.1.1.0/24":"block"
    },
    "malicious.net":{
        "all":"block",
        "127.0.0.1":"allow"
    },
    "porn.com":{
        "all":"redirect"
    },
    "video.porn.com": {
        "all":"block"
    },
    "edu.video.porn.com": {
        "all":"allow"
    }
}
~~~

### Test Block

No answer section return, and Rcode return REFUSED

```
➜  pv_firewall git:(master) ✗ dig video.porn.com  @127.0.0.1 

; <<>> DiG 9.10.6 <<>> video.porn.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 56780
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;video.porn.com.                        IN      A

;; Query time: 26 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Mar 25 16:44:05 CST 2022
;; MSG SIZE  rcvd: 43
```

### Test Redirect

Rdata be redirect to 127.0.0.1 in A query defaultly, and Rcode return REFUSED

```

➜  pv_firewall git:(master) ✗ dig porn.com  @127.0.0.1 

; <<>> DiG 9.10.6 <<>> porn.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 5188
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;porn.com.                      IN      A

;; ANSWER SECTION:
porn.com.               600     IN      A       127.0.0.1

;; Query time: 47 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Mar 25 16:41:33 CST 2022
;; MSG SIZE  rcvd: 61

```


::1 return during IPV6 query
```
➜  pv_firewall git:(master) ✗ dig porn.com  @127.0.0.1 AAAA      

; <<>> DiG 9.10.6 <<>> porn.com @127.0.0.1 AAAA
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 60506
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;porn.com.                      IN      AAAA

;; ANSWER SECTION:
porn.com.               600     IN      AAAA    ::1

;; Query time: 30 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Mar 25 16:46:37 CST 2022
;; MSG SIZE  rcvd: 73

```


## Policy

Firewall supported policy, check the `policys/policy.json` configurations and `policy_test.go` testcases.




