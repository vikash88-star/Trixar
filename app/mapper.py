import json

# Your own overrides: Wazuh rule ID -> technique ID.
# Verify each ID against the rule in the Wazuh dashboard (Server management -> Rules)
# and keep growing this table toward your "first 20 alert types" goal.
RULE_MAP = {
    "5710": "T1110.001",  # login attempt with non-existent user
    "5712": "T1110",      # sshd brute force
    "5760": "T1110.001",  # sshd authentication failed
    "5763": "T1110",      # sshd brute force
    "31103": "T1190",     # SQL injection attempt on web server
    "31104": "T1190",     # common web attack
    "533": "T1046",       # netstat: listened ports changed (discovery / possible backdoor listener)
}

async def map_alert(rdb, rule_id: str, wazuh_mitre_ids: list[str]) -> dict | None:
    technique_id = RULE_MAP.get(rule_id) or (wazuh_mitre_ids[0] if wazuh_mitre_ids else None)
    if not technique_id:
        return None
    raw = await rdb.get(f"attack:{technique_id}")  # local cache, no live API call
    return json.loads(raw) if raw else {"id": technique_id, "name": "unknown", "tactics": []}
