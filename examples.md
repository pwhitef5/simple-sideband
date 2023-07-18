# Example Simple Sideband Requests

# DNS request
## iRule
`when HTTP_REQUEST {
    # Create DNS request
    set q [call /Common/simple_sideband::dns_query "www.example.com" ]
    binary scan $q H* qhex
    log local0.debug "query:$qhex"
    # Send request to DNS server
    set response [call /Common/simple_sideband::udp_req 10.67.182.10:53 $q {recv_bytes 1} ]
    if { [lindex $response 0] == 0 } {
        # Successful response - decode the DNS esponse
        set data [lindex $response 1]
        binary scan $data H* data_hex
        log local0.debug "Success!: $data_hex"
        set r [call /Common/simple_sideband::dns_response $data ]
        HTTP::respond 200 content $r
    } else {
        HTTP::respond 500 content {failure}
    }
}`
## Answer only
### output
`curl 10.67.182.40
{18766 32776 1 1 0 0} {www.example.com 1 1} {{1 1 12 1.2.3.4}} {} {}`
### logs
`Jul 14 08:54:26 simple-sideband-bigip1.pwhite debug tmm[30491]: Rule /Common/sideband_test <HTTP_REQUEST>: query:494e0008000100000000000003777777076578616d706c6503636f6d0000010001
Jul 14 08:54:27 simple-sideband-bigip1.pwhite debug tmm[30491]: Rule /Common/sideband_test <HTTP_REQUEST>: Success!: 494e8008000100010000000003777777076578616d706c6503636f6d0000010001c00c000100010000000c000401020304`

## Additional
### output
`curl 10.67.182.40
{38749 32776 1 2 0 1} {www.example.com 1 1} {{1 1 12 1.2.3.4} {1 1 12 1.2.3.5}} {} {{2 1 12 {1 51 1 52 1 53 1 54 0}}}`
### logs
`Jul 14 09:05:10 simple-sideband-bigip1.pwhite debug tmm[30491]: Rule /Common/sideband_test <HTTP_REQUEST>: query:975d0008000100000000000003777777076578616d706c6503636f6d0000010001
Jul 14 09:05:10 simple-sideband-bigip1.pwhite debug tmm[30491]: Rule /Common/sideband_test <HTTP_REQUEST>: Success!: 975d8008000100020000000103777777076578616d706c6503636f6d0000010001c00c000100010000000c000401020304c00c000100010000000c000401020305c00c000200010000000c0009013301340135013600`
---
# TCP request

`when HTTP_REQUEST {
    # Create HTTP request
    set response [call /Common/simple_sideband::tcp_req 10.67.182.10:80 "GET /\r\n" {recv_bytes 3} ]
    if { [lindex $response 0] == 0 } {
        HTTP::respond 200 content $response
    } else {
        HTTP::respond 500 content $response
    }
}`

## output
`curl 10.67.182.40
0 {HTTP/1.0 200 OK
Server: BigIP
Connection: close
Content-Length: 20

hello world! port:80}`

---
# HTTP request
## iRule
`when HTTP_REQUEST {
    # Create HTTP request
    set response [call /Common/simple_sideband::http_req 10.67.182.10:80 "/" {} ]
    if { [lindex $response 0] == 200 } {
        HTTP::respond 200 content $response
    } else {
        HTTP::respond 500 content $response
    }
}`
## output
`200 {Server BigIP Connection Keep-Alive Content-Length 20} {hello world! port:80}`

---
# HTTPS
## Helper VS:
`ltm virtual https_helper {
    creation-time 2023-07-14:09:23:06
    destination 0.0.0.0:search-agent
    ip-protocol tcp
    last-modified-time 2023-07-14:09:23:06
    mask 255.255.255.255
    pool https_pool
    profiles {
        http { }
        serverssl {
            context serverside
        }
        tcp { }
    }
    serverssl-use-sni disabled
    source 0.0.0.0/0
    source-address-translation {
        type automap
    }
    translate-address enabled
    translate-port enabled
    vlans-enabled
    vs-index 3
}`
## iRule
`when HTTP_REQUEST {
    # Create HTTP request
    set response [call /Common/simple_sideband::http_req "/Common/https_helper" "/" {} ]
    if { [lindex $response 0] == 200 } {
        HTTP::respond 200 content $response
    } else {
        HTTP::respond 500 content $response
    }
}`

## Output
`curl 10.67.182.40
200 {Server BigIP Connection Keep-Alive Content-Length 21} {hello world! port:443}`

---
# Helper iRule
`ltm virtual https_helper {
    creation-time 2023-07-14:09:23:06
    destination 0.0.0.0:search-agent
    ip-protocol tcp
    last-modified-time 2023-07-14:09:23:06
    mask 255.255.255.255
    pool https_pool
    profiles {
        http { }
        serverssl {
            context serverside
        }
        tcp { }
    }
    rules {
        simple_sideband ==<-- simple_sideband iRule==
    }
    serverssl-use-sni disabled
    source 0.0.0.0/0
    source-address-translation {
        type automap
    }
    translate-address enabled
    translate-port enabled
    vlans-enabled
    vs-index 3
}`

## iRule
`when HTTP_REQUEST {
    # Create HTTP request
    set options [list headers [list "X-SS-Destination" "10.67.182.10" "X-SS-Snat" "10.67.182.3"]]
    set response [call /Common/simple_sideband::http_req "/Common/https_helper" "/mgmt/tm/ltm/virtual" $options ]
    if { [lindex $response 0] == 200 } {
        HTTP::respond 200 content $response
    } else {
        HTTP::respond 500 content $response
    }
}`
## Output
`curl 10.67.182.40
200 {Server BigIP Connection Keep-Alive Content-Length 21} {hello world! port:443}`


---
# User authentication
## iRule
`when HTTP_REQUEST {
    # Create HTTP request
    set auth_header [b64encode "admin:admin"]
    log local0.debug "Auth header: $auth_header"
    set options [list headers [list "X-SS-Destination" "10.67.182.2"\
                                    "X-SS-Snat" "10.67.182.3" \
                                    "Authorization" "Basic $auth_header"\
                                    "Host" "10.67.182.2" \
                                    "User-Agent" "curl-2.15" \
                                    ]]
    set response [call /Common/simple_sideband::http_req "/Common/https_helper" "/mgmt/tm/ltm/virtual" $options ]
    if { [lindex $response 0] == 200 } {
        HTTP::respond 200 content $response
    } else {
        HTTP::respond 500 content $response
    }
}`


## Output
`curl 10.67.182.40
401 {Date {Tue, 18 Jul 2023 09} Server Jetty(9.2.22.v20170606) WWW-Authenticate {Basic realm="Enterprise Manager"} Set-Cookie {BIGIPAuthCookie=OZUHPMD6E9zsSNlafghmD2jYSN4v3G5q9IkjidiZ; path=/; Secure; HttpOnly; SameSite=Strict} Set-Cookie {BIGIPAuthUsernameCookie=admin; path=/; Secure; HttpOnly; SameSite=Strict} X-Frame-Options SAMEORIGIN Strict-Transport-Security {max-age=16070400; includeSubDomains} Content-Type {application/json; charset=UTF-8} WWW-Authenticate X-Auth-Token Pragma no-cache Cache-Control no-store Cache-Control no-cache Cache-Control must-revalidate Expires -1 Content-Length 259 X-Content-Type-Options nosniff X-XSS-Protection {1; mode=block} Content-Security-Policy {default-src 'self'  'unsafe-inline' 'unsafe-eval' data}} {{"code":401,"message":"Authorization failed: no user authentication header or token detected. Uri:http://localhost:8100/mgmt/tm/ltm/virtual Referrer:10.67.182.3 Sender:10.67.182.3","referer":"10.67.182.3","restOperationId":7502011,"kind":":resterrorresponse"}}[root@simple-sideband-bigip1:Active:Standalone] config # curl 10.67.182.40
200 {Date {Tue, 18 Jul 2023 09} Server Jetty(9.2.22.v20170606) Set-Cookie {BIGIPAuthCookie=KV9AHUux96AH96Zix2ozLYkjQTofQPEDwrTIaN2D; path=/; Secure; HttpOnly; SameSite=Strict} Set-Cookie {BIGIPAuthUsernameCookie=admin; path=/; Secure; HttpOnly; SameSite=Strict} X-Frame-Options SAMEORIGIN Strict-Transport-Security {max-age=16070400; includeSubDomains} Content-Type {application/json; charset=UTF-8} Allow {} X-F5-Api-Status DEPRECATED_PROPERTY Pragma no-cache Cache-Control no-store Cache-Control no-cache Cache-Control must-revalidate Expires -1 Content-Length 4459 X-Content-Type-Options nosniff X-XSS-Protection {1; mode=block} Content-Security-Policy {default-src 'self'  'unsafe-inline' 'unsafe-eval' data}} {{"kind":"tm:ltm:virtual:virtualcollectionstate","selfLink":"https://localhost/mgmt/tm/ltm/virtual?ver=17.1.0.1","items":[{"kind":"tm:ltm:virtual:virtualstate","name":"dns","partition":"Common","fullPath":"/Common/dns","generation":171,"selfLink":"https://localhost/mgmt/tm/ltm/virtual/~Common~dns?ver=17.1.0.1","addressStatus":"yes","autoLasthop":"default","cmpEnabled":"yes","connectionLimit":0,"creationTime":"2023-07-14T11:51:07Z","destination":"/Common/10.67.182.10:53","enabled":true,"evictionProtected":"disabled","gtmScore":0,"ipProtocol":"udp","lastModifiedTime":"2023-07-14T11:51:07Z","mask":"255.255.255.255","mirror":"disabled","mobileAppTunnel":"disabled","nat64":"disabled","rateLimit":"disabled","rateLimitDstMask":0,"rateLimitMode":"object","rateLimitSrcMask":0,"serversslUseSni":"disabled","serviceDownImmediateAction":"none","source":"0.0.0.0/0","sourceAddressTranslation":{"type":"none"},"sourcePort":"preserve","synCookieStatus":"not-activated","translateAddress":"enabled","translatePort":"enabled","vlansEnabled":true,"vsIndex":2,"rules":["/Common/dns_response"],"rulesReference":[{"link":"https://localhost/mgmt/tm/ltm/rule/~Common~dns_response?ver=17.1.0.1"}],"vlans":["/Common/Internal"],"vlansReference":[{"link":"https://localhost/mgmt/tm/net/vlan/~Common~Internal?ver=17.1.0.1"}],"policiesReference":{"link":"https://localhost/mgmt/tm/ltm/virtual/~Common~dns/policies?ver=17.1.0.1","isSubcollection":true},"profilesReference":{"link":"https://localhost/mgmt/tm/ltm/virtual/~Common~dns/profiles?ver=17.1.0.1","isSubcollection":true}},{"kind":"tm:ltm:virtual:virtualstate","name":"http","partition":"Common","fullPath":"/Common/http","generation":172,"selfLink":"https://localhost/mgmt/tm/ltm/virtual/~Common~http?ver=17.1.0.1","addressStatus":"yes","autoLasthop":"default","cmpEnabled":"yes","connectionLimit":0,"creationTime":"2023-07-14T11:51:43Z","destination":"/Common/10.67.182.10:80","enabled":true,"evictionProtected":"disabled","gtmScore":0,"ipProtocol":"tcp","lastModifiedTime":"2023-07-14T11:51:43Z","mask":"255.255.255.255","mirror":"disabled","mobileAppTunnel":"disabled","nat64":"disabled","rateLimit":"disabled","rateLimitDstMask":0,"rateLimitMode":"object","rateLimitSrcMask":0,"serversslUseSni":"disabled","serviceDownImmediateAction":"none","source":"0.0.0.0/0","sourceAddressTranslation":{"type":"none"},"sourcePort":"preserve","synCookieStatus":"not-activated","translateAddress":"enabled","translatePort":"enabled","vlansEnabled":true,"vsIndex":3,"rules":["/Common/http_response"],"rulesReference":[{"link":"https://localhost/mgmt/tm/ltm/rule/~Common~http_response?ver=17.1.0.1"}],"vlans":["/Common/Internal"],"vlansReference":[{"link":"https://localhost/mgmt/tm/net/vlan/~Common~Internal?ver=17.1.0.1"}],"policiesReference":{"link":"https://localhost/mgmt/tm/ltm/virtual/~Common~http/policies?ver=17.1.0.1","isSubcollection":true},"profilesReference":{"link":"https://localhost/mgmt/tm/ltm/virtual/~Common~http/profiles?ver=17.1.0.1","isSubcollection":true}},{"kind":"tm:ltm:virtual:virtualstate","name":"https","partition":"Common","fullPath":"/Common/https","generation":173,"selfLink":"https://localhost/mgmt/tm/ltm/virtual/~Common~https?ver=17.1.0.1","addressStatus":"yes","autoLasthop":"default","cmpEnabled":"yes","connectionLimit":0,"creationTime":"2023-07-14T11:52:14Z","destination":"/Common/10.67.182.10:443","enabled":true,"evictionProtected":"disabled","gtmScore":0,"ipProtocol":"tcp","lastModifiedTime":"2023-07-14T11:52:14Z","mask":"255.255.255.255","mirror":"disabled","mobileAppTunnel":"disabled","nat64":"disabled","rateLimit":"disabled","rateLimitDstMask":0,"rateLimitMode":"object","rateLimitSrcMask":0,"serversslUseSni":"disabled","serviceDownImmediateAction":"none","source":"0.0.0.0/0","sourceAddressTranslation":{"type":"none"},"sourcePort":"preserve","synCookieStatus":"not-activated","translateAddress":"enabled","translatePort":"enabled","vlansEnabled":true,"vsIndex":4,"rules":["/Common/http_response"],"rulesReference":[{"link":"https://localhost/mgmt/tm/ltm/rule/~Common~http_response?ver=17.1.0.1"}],"vlans":["/Common/Internal"],"vlansReference":[{"link":"https://localhost/mgmt/tm/net/vlan/~Common~Internal?ver=17.1.0.1"}],"policiesReference":{"link":"https://localhost/mgmt/tm/ltm/virtual/~Common~https/policies?ver=17.1.0.1","isSubcollection":true},"profilesReference":{"link":"https://localhost/mgmt/tm/ltm/virtual/~Common~https/profiles?ver=17.1.0.1","isSubcollection":true}}]}}`
---
