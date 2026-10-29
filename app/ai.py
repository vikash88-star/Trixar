import httpx

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:3b"

PROMPT = """You are a SOC analyst assistant. In 3 short sentences:
1) explain this alert in plain language, 2) say why it matters, 3) recommend the first action.

Alert: {desc}
Severity (0-15): {sev}
ATT&CK technique: {tech}
Source IP: {ip}
Reputation data: {rep}
"""

async def summarise(alert: dict, technique, enrichment: dict) -> str:
    prompt = PROMPT.format(
        desc=alert["rule_desc"], sev=alert["severity"],
        tech=f'{technique["id"]} {technique["name"]}' if technique else "unmapped",
        ip=alert.get("src_ip"), rep=enrichment)
    try:
        # A long timeout is fine: this runs in the background, never in the request.
        async with httpx.AsyncClient(timeout=180) as c:
            r = await c.post(OLLAMA_URL, json={"model": MODEL, "prompt": prompt, "stream": False})
            r.raise_for_status()
            return r.json()["response"].strip()
    except Exception as e:
        return f"(AI summary unavailable: {e})"
