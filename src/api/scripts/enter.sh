#!/bin/bash

for i in {1..10}; do 
curl --header "Content-Type: application/json" --request POST http://localhost:8000/entry/dhcp --data "{
\"timestamp\": $i,
\"probeName\": \"string\",
\"macsrc\": \"string\",
\"macdst\": \"string\",
\"ipsrc\": \"string\",
\"ipdst\": \"string\",
\"portsrc\": 1,
\"portdst\": 1,
\"dhcp\": {
\"op\": 0,
\"htype\": 0,
\"hlen\": 0,
\"hops\": 0,
\"xid\": 0,
\"secs\": 0,
\"flags\": 0,
\"ciaddr\": \"string\",
\"yiaddr\": \"string\",
\"siaddr\": \"string\",
\"giaddr\": \"string\",
\"chaddr\": \"string\",
\"magicCookie\": 0,
\"options\": {
\"additionalProp1\": \"string\",
\"additionalProp2\": \"string\",
\"additionalProp3\": \"string\"
}}}"
done

