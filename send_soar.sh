#!/bin/bash
# usage: ./send_soar.sh 003   (the number makes the source_id unique)
curl -s -X POST http://localhost:8000/alert -H "Content-Type: application/json" -d "{
  \"source_id\": \"soar-$1\",
  \"rule_id\": \"31104\",
  \"rule_desc\": \"Web attack: common SQL injection pattern\",
  \"severity\": 13,
  \"agent_name\": \"kali-lab\",
  \"agent_ip\": \"192.168.56.10\",
  \"src_ip\": \"1.1.1.1\"
}" | python3 -m json.tool | head -5
