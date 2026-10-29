# Kill-chain rank per ATT&CK tactic: later in the attack = higher (0 to 1)
TACTIC_RANK = {
    "reconnaissance": 0.1, "resource-development": 0.15,
    "initial-access": 0.35, "execution": 0.45, "persistence": 0.5,
    "privilege-escalation": 0.6, "defense-evasion": 0.55,
    "credential-access": 0.6, "discovery": 0.4, "lateral-movement": 0.75,
    "collection": 0.8, "command-and-control": 0.85,
    "exfiltration": 0.95, "impact": 1.0,
}

# Weights must add up to 1.0. You tune these later against labelled alerts.
W_SEVERITY, W_ASSET, W_STAGE, W_REPUTATION = 0.35, 0.25, 0.25, 0.15

def reputation_factor(enrichment: dict) -> float:
    """0 to 1: how bad is the source IP according to the threat-intel APIs?"""
    abuse = (enrichment.get("abuseipdb") or {}).get("abuse_score", 0) / 100
    vt = min((enrichment.get("virustotal") or {}).get("vt_malicious", 0) / 10, 1.0)
    return max(abuse, vt)

def stage_factor(tactics: list) -> float:
    ranks = [TACTIC_RANK.get(t, 0.3) for t in tactics]
    return max(ranks) if ranks else 0.3   # unknown tactic = mild default

def priority_score(severity: int, criticality: int, tactics: list, enrichment: dict) -> float:
    s = min(severity, 15) / 15
    a = (criticality - 1) / 4             # 1..5 -> 0..1
    score = (W_SEVERITY * s + W_ASSET * a +
             W_STAGE * stage_factor(tactics) + W_REPUTATION * reputation_factor(enrichment))
    return round(score * 100, 1)
