import asyncio, joblib
import pandas as pd

# Must match the column order used in train_fp.py
FEATURES = ["severity", "abuse_score", "criticality", "hour", "freq_last_hour"]
queue: asyncio.Queue = asyncio.Queue()

async def fp_worker(pool):
    model = joblib.load("data/fp_model.joblib")
    loop = asyncio.get_running_loop()
    while True:
        batch = [await queue.get()]                  # wait for at least one alert
        deadline = loop.time() + 2.0                 # then collect for up to 2 seconds...
        while len(batch) < 50:                       # ...or until we have 50
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                batch.append(await asyncio.wait_for(queue.get(), timeout=remaining))
            except asyncio.TimeoutError:
                break
        try:
            X = pd.DataFrame([b["features"] for b in batch], columns=FEATURES)
            probs = await asyncio.to_thread(lambda: model.predict_proba(X)[:, 1])  # ONE call per batch
            async with pool.acquire() as conn:
                await conn.executemany(
                    "UPDATE alerts SET fp_probability=$1 WHERE id=$2",
                    [(round(float(p), 3), b["alert_id"]) for p, b in zip(probs, batch)])
        except Exception as e:
            print("fp_worker error:", e)             # never let the worker die
