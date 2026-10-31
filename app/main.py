import asyncio, os
from contextlib import asynccontextmanager
from datetime import datetime
import httpx, redis.asyncio as aioredis
from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from ipaddress import IPv4Address, IPv6Address
from .config import REDIS_URL
from .db import (create_pool, alert_exists, save_alert, get_criticality,
                 update_score, update_summary, rule_frequency)
from .enrich import enrich_ip
from .mapper import map_alert
from .scoring import priority_score
from .ai import summarise
from .ws import manager
from . import fp_worker

class AlertIn(BaseModel):
    source_id: str
    rule_id: str
    rule_desc: str
    severity: int
    agent_name: str
    agent_ip: IPv4Address | IPv6Address | None = None
    src_ip: IPv4Address | IPv6Address | None = None
    wazuh_mitre_ids: list[str] = []

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.rdb = aioredis.from_url(REDIS_URL, decode_responses=True)
    app.state.pool = await create_pool()
    app.state.http = httpx.AsyncClient(timeout=10)
    app.state.fp_task = asyncio.create_task(fp_worker.fp_worker(app.state.pool))
    yield
    app.state.fp_task.cancel()
    await app.state.http.aclose()
    await app.state.pool.close()
    await app.state.rdb.aclose()

app = FastAPI(title="Trixar", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_methods=["*"], allow_headers=["*"])

async def fire_soar(payload: dict):
    """Tell n8n about a high-priority alert. Never lets a SOAR failure break triage."""
    url = os.getenv("SOAR_WEBHOOK")
    if not url:
        return
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(url, json=payload)
            print("soar:", r.status_code, r.text[:300])
    except Exception as e:
        print("soar error:", e)

async def ai_job(alert_id: int, alert: dict, technique, enrichment):
    """Runs AFTER the response is sent. Slow, so it never blocks triage."""
    summary = await summarise(alert, technique, enrichment)
    await update_summary(app.state.pool, alert_id, summary)
    await manager.broadcast({"type": "ai_summary", "alert_id": alert_id, "summary": summary})

@app.post("/alert")
async def ingest(alert: AlertIn, bg: BackgroundTasks):
    s = app.state
    if await alert_exists(s.pool, alert.source_id):
        return {"status": "duplicate", "source_id": alert.source_id}

    a = alert.model_dump(mode="json")
    technique = await map_alert(s.rdb, alert.rule_id, alert.wazuh_mitre_ids)
    enrichment = await enrich_ip(s.http, s.rdb, a.get("src_ip"))
    alert_id = await save_alert(s.pool, a, technique, enrichment)

    crit = await get_criticality(s.pool, alert.agent_name)
    score = priority_score(alert.severity, crit,
                           technique["tactics"] if technique else [], enrichment)
    await update_score(s.pool, alert_id, score)

    # Queue for the batch false-positive model (scored later, in bulk)
    freq = await rule_frequency(s.pool, alert.rule_id)
    await fp_worker.queue.put({"alert_id": alert_id, "features": [
        alert.severity,
        (enrichment.get("abuseipdb") or {}).get("abuse_score", 0),
        crit, datetime.now().hour, freq]})

    if score >= float(os.getenv("SOAR_THRESHOLD", "70")):
        bg.add_task(fire_soar, {"alert_id": alert_id, "score": score,
                                "src_ip": a.get("src_ip"), "rule": alert.rule_desc,
                                "technique": technique["id"] if technique else None})
    bg.add_task(ai_job, alert_id, a, technique, enrichment)    # async, non-blocking
    await manager.broadcast({"type": "new_alert", "alert_id": alert_id, "score": score})

    return {"id": alert_id, "priority_score": score, "technique": technique,
            "enrichment": enrichment, "ai_summary": "pending"}

@app.get("/alerts")
async def list_alerts(limit: int = 50):
    rows = await app.state.pool.fetch(
        """SELECT id, rule_id, rule_desc, severity, technique_id, tactic,
                  priority_score, fp_probability, ai_summary, status
           FROM alerts ORDER BY priority_score DESC NULLS LAST LIMIT $1""", limit)
    return [dict(r) for r in rows]

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()      # keeps the connection open
    except WebSocketDisconnect:
        manager.disconnect(ws)

@app.get("/health")
async def health():
    return {"ok": True}


@app.get("/stats/techniques")
async def technique_stats():
    rows = await app.state.pool.fetch(
        """SELECT technique_id, count(*) AS count, max(priority_score) AS max_score
           FROM alerts WHERE technique_id IS NOT NULL
           GROUP BY technique_id ORDER BY count DESC""")
    return [dict(r) for r in rows]
