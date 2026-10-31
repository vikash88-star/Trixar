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

    # Extended coverage toward the spec's "first 20 alert types" goal
    "5758": "T1110.001",  # sshd authentication failed (multiple)
    "5761": "T1110.001",  # sshd invalid user login attempt
    "2501": "T1562.001",  # firewall rule change / disable
    "40111": "T1055",     # process injection / anomalous process
    "100002": "T1053",    # scheduled task / cron modification
    "31101": "T1595",     # active scanning detected (web)
    "31105": "T1059",     # command injection attempt (web)
    "31106": "T1083",     # file/directory discovery via web path traversal
    "40101": "T1070",     # log file cleared / tampered
    "5901": "T1098",      # new user account created
    "5902": "T1531",      # account disabled / removed
    "4625": "T1110",      # Windows failed logon (if monitoring Windows hosts)
    "18152": "T1021",     # remote service access (RDP/SMB style)
}

async def map_alert(rdb, rule_id: str, wazuh_mitre_ids: list[str]) -> dict | None:
    technique_id = RULE_MAP.get(rule_id) or (wazuh_mitre_ids[0] if wazuh_mitre_ids else None)
    if not technique_id:
        return None
    raw = await rdb.get(f"attack:{technique_id}")  # local cache, no live API call
    return json.loads(raw) if raw else {"id": technique_id, "name": "unknown", "tactics": []}
