import asyncio, ipaddress, json
import httpx
from .config import ABUSEIPDB_KEY, VT_KEY, SHODAN_KEY

async def abuseipdb(client, ip):
    r = await client.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 90})
    r.raise_for_status()
    d = r.json()["data"]
    return {"abuse_score": d["abuseConfidenceScore"],
            "total_reports": d["totalReports"], "country": d.get("countryCode")}

async def virustotal(client, ip):
    r = await client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={"x-apikey": VT_KEY})
    r.raise_for_status()
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    return {"vt_malicious": stats["malicious"], "vt_suspicious": stats["suspicious"]}

async def shodan(client, ip):
    r = await client.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": SHODAN_KEY})
    if r.status_code == 404:          # Shodan has never seen this IP
        return {"open_ports": []}
    r.raise_for_status()
    return {"open_ports": r.json().get("ports", [])}

async def enrich_ip(client, rdb, ip: str | None) -> dict:
    if not ip:
        return {"skipped": "no source ip"}
    if ipaddress.ip_address(ip).is_private:
        return {"skipped": "private ip"}

    cached = await rdb.get(f"rep:{ip}")
    if cached:
        return json.loads(cached)

    providers = {}
    if ABUSEIPDB_KEY: providers["abuseipdb"] = abuseipdb(client, ip)
    if VT_KEY:        providers["virustotal"] = virustotal(client, ip)
    if SHODAN_KEY:    providers["shodan"] = shodan(client, ip)

    # All providers run at the same time, not one after another.
    results = await asyncio.gather(*providers.values(), return_exceptions=True)

    out = {}
    for name, res in zip(providers, results):
        out[name] = {"error": str(res)} if isinstance(res, Exception) else res

    await rdb.set(f"rep:{ip}", json.dumps(out), ex=6 * 3600)  # cache 6 hours
    return out
