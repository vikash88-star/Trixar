import numpy as np, pandas as pd, joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

rng = np.random.default_rng(42)
n = 3000
df = pd.DataFrame({
    "severity": rng.integers(1, 16, n),
    "abuse_score": rng.integers(0, 101, n),
    "criticality": rng.integers(1, 6, n),
    "hour": rng.integers(0, 24, n),
    "freq_last_hour": rng.integers(1, 200, n),
})
# Synthetic rule: low severity + clean IP + very noisy rule = likely false positive
noise = (df.severity < 6) & (df.abuse_score < 20) & (df.freq_last_hour > 60)
df["is_fp"] = (noise | (rng.random(n) < 0.05)).astype(int)

X, y = df.drop(columns="is_fp"), df["is_fp"]
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=200, random_state=42).fit(Xtr, ytr)
print(classification_report(yte, model.predict(Xte)))
joblib.dump(model, "data/fp_model.joblib")
print("Saved data/fp_model.joblib")
