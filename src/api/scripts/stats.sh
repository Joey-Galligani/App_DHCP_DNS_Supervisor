#!/bin/bash

curl --header "Content-Type: application/json" --request POST http://localhost:8000/stats/dns --data "{
  \"tld\": \"fr\",
  \"fqdn\": \"gg.fr\",
  \"ipsrc\": \"1.1.1.1\",
  \"ipdst\": \"192.168.1.1\"
}"
