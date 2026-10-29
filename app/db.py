import json
import asyncpg
from .config import DATABASE_URL

async def create_pool():
    return await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)

async def alert_exists(pool, source_id: str) -> bool:
    return bool(await pool.fetchval("SELECT 1 FROM alerts WHERE source_id=$1", source_id))

async def save_alert(pool, a: dict, technique: dict | None, enrichment: dict) -> int:
    async with pool.acquire() as conn:
        asset_id = await conn.fetchval(
            """INSERT INTO assets (hostname, ip) VALUES ($1, $2::inet)
               ON CONFLICT (hostname) DO UPDATE SET hostname = EXCLUDED.hostname
               RETURNING id""",
            a["agent_name"], a.get("agent_ip"))
        return await conn.fetchval(
            """INSERT INTO alerts (source_id, rule_id, rule_desc, severity, src_ip,
                                   asset_id, technique_id, tactic, enrichment)
               VALUES ($1,$2,$3,$4,$5::inet,$6,$7,$8,$9::jsonb) RETURNING id""",
            a["source_id"], a["rule_id"], a["rule_desc"], a["severity"], a.get("src_ip"),
            asset_id, technique["id"] if technique else None,
            ",".join(technique["tactics"]) if technique else None,
            json.dumps(enrichment))

async def get_criticality(pool, hostname: str) -> int:
    v = await pool.fetchval("SELECT criticality FROM assets WHERE hostname=$1", hostname)
    return v or 2

async def update_score(pool, alert_id: int, score: float):
    await pool.execute("UPDATE alerts SET priority_score=$1 WHERE id=$2", score, alert_id)

async def update_summary(pool, alert_id: int, summary: str):
    await pool.execute("UPDATE alerts SET ai_summary=$1 WHERE id=$2", summary, alert_id)

async def rule_frequency(pool, rule_id: str) -> int:
    """How many alerts of this rule in the last hour? A very noisy rule is often a false positive."""
    n = await pool.fetchval(
        "SELECT count(*) FROM alerts WHERE rule_id=$1 AND received_at > now() - interval '1 hour'",
        rule_id)
    return int(n) + 1
