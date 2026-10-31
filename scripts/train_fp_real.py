import asyncpg, asyncio, joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app.config import DATABASE_URL

async def main():
    conn = await asyncpg.connect(DATABASE_URL)
    rows = await conn.fetch("""
        SELECT a.severity, a.received_at,
               (a.enrichment->'abuseipdb'->>'abuse_score')::int AS abuse_score,
               ast.criticality,
               (a.status = 'false_positive')::int AS is_fp
        FROM alerts a LEFT JOIN assets ast ON a.asset_id = ast.id
        WHERE a.status IN ('true_positive','false_positive')
    """)
    await conn.close()
    if len(rows) < 20:
        print(f"Only {len(rows)} labelled alerts. Label more before retraining (aim for 50+).")
        return

    df = pd.DataFrame([dict(r) for r in rows])
    df['abuse_score'] = df['abuse_score'].fillna(0)
    df['criticality'] = df['criticality'].fillna(2)
    df['hour'] = df['received_at'].apply(lambda t: t.hour)
    df['freq_last_hour'] = 1   # placeholder; wire in real frequency if you track it

    X = df[['severity', 'abuse_score', 'criticality', 'hour', 'freq_last_hour']]
    y = df['is_fp']
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42)
    model = RandomForestClassifier(n_estimators=200, random_state=42).fit(Xtr, ytr)
    print(classification_report(yte, model.predict(Xte)))
    joblib.dump(model, "data/fp_model.joblib")
    print(f"Retrained on {len(rows)} real labels. Saved data/fp_model.joblib")

asyncio.run(main())
