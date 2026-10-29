import os, sys
import httpx
from dotenv import load_dotenv
load_dotenv()

INDEXER = os.getenv("WAZUH_INDEXER")
AUTH = (os.getenv("WAZUH_USER"), os.getenv("WAZUH_PASS"))
API = "http://localhost:8000/alert"

query = {
    "size": 100,
    "sort": [{"timestamp": "asc"}],
    "query": {"range": {"timestamp": {"gte": "now-15m"}}},
}

# verify=False because the lab uses self-signed certificates. Lab only.
r = httpx.post(f"{INDEXER}/wazuh-alerts-*/_search", json=query,
               auth=AUTH, verify=False, timeout=30)
r.raise_for_status()

for hit in r.json()["hits"]["hits"]:
    s = hit["_source"]
    payload = {
        "source_id": hit["_id"],
        "rule_id": s["rule"]["id"],
        "rule_desc": s["rule"]["description"],
        "severity": s["rule"]["level"],
        "agent_name": s["agent"]["name"],
        "agent_ip": s["agent"].get("ip"),
        "src_ip": s.get("data", {}).get("srcip"),
        "wazuh_mitre_ids": s["rule"].get("mitre", {}).get("id", []),
    }
    res = httpx.post(API, json=payload, timeout=60).json()
    tech = (res.get("technique") or {}).get("id")
    print(payload["rule_id"], "->", tech or res.get("status"))
