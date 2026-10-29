import json, sys, os
import httpx, redis
from mitreattack.stix20 import MitreAttackData

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app.config import REDIS_URL

URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
       "master/enterprise-attack/enterprise-attack.json")
PATH = "data/enterprise-attack.json"

def main():
    print("Downloading ATT&CK bundle...")
    r = httpx.get(URL, timeout=180, follow_redirects=True)
    r.raise_for_status()
    open(PATH, "wb").write(r.content)

    data = MitreAttackData(PATH)
    techniques = data.get_techniques(remove_revoked_deprecated=True)

    rdb = redis.from_url(REDIS_URL)
    pipe = rdb.pipeline()  # batch many commands into one round trip
    count = 0
    for t in techniques:
        attack_id = next((x.external_id for x in t.external_references
                          if x.source_name == "mitre-attack"), None)
        if not attack_id:
            continue
        tactics = [p.phase_name for p in getattr(t, "kill_chain_phases", [])]
        pipe.set(f"attack:{attack_id}", json.dumps({
            "id": attack_id,
            "name": t.name,
            "tactics": tactics,
            "url": f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
        }))
        count += 1
    pipe.execute()
    print(f"Cached {count} techniques in Redis")

if __name__ == "__main__":
    main()
