import httpx

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:3b"

PROMPT = """You are a SOC analyst assistant. Use ONLY the facts below. Do not invent details.
Answer in exactly 3 short sentences:
1) what the alert means in plain language, 2) why it matters, 3) the first action to take.

Alert: {desc}
Severity (0-15): {sev}
ATT&CK technique: {tech}
Source IP: {ip}
Reputation: {rep}
"""

def describe_reputation(e: dict) -> str:
    if not e or "skipped" in e:
        return "no external reputation data available"
    parts = []
    a = e.get("abuseipdb") or {}
    if "abuse_score" in a:
        parts.append(f"AbuseIPDB score {a['abuse_score']}/100 ({a.get('total_reports', 0)} reports)")
    v = e.get("virustotal") or {}
    if "vt_malicious" in v:
        parts.append(f"{v['vt_malicious']} VirusTotal engines flag it malicious")
    s = e.get("shodan") or {}
    if s.get("open_ports"):
        parts.append(f"open ports {s['open_ports']}")
    return "; ".join(parts) or "no external reputation data available"

async def summarise(alert: dict, technique, enrichment: dict) -> str:
    prompt = PROMPT.format(
        desc=alert["rule_desc"], sev=alert["severity"],
        tech=f'{technique["id"]} {technique["name"]}' if technique else "unmapped",
        ip=alert.get("src_ip"), rep=describe_reputation(enrichment))
    try:
        async with httpx.AsyncClient(timeout=180) as c:
            r = await c.post(OLLAMA_URL, json={
                "model": MODEL, "prompt": prompt, "stream": False,
                "options": {"temperature": 0.2, "num_predict": 150}})
            r.raise_for_status()
            return r.json()["response"].strip()
    except Exception as e:
        return f"(AI summary unavailable: {e})"
