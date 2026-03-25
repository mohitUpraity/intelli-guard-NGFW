"""
Kunal — Real-Time Inference
Reads from feature_pipeline.pipeline.ml_queue → scores → sends verdict to firewall_engine.
Threat Score:
  > 0.9  → BLOCK
  0.7–0.9 → ALERT
  < 0.7  → ALLOW
"""
import joblib, pandas as pd
from feature_pipeline.pipeline import ml_queue

XGB_PATH    = "ai_engine/models/xgboost_model.pkl"
IFOREST_PATH= "ai_engine/models/iforest_model.pkl"

def load_models():
    xgb = joblib.load(XGB_PATH)
    iso = joblib.load(IFOREST_PATH)
    return xgb, iso

def score(features: dict, xgb, iso) -> tuple[float, str]:
    df = pd.DataFrame([features])
    prob      = xgb.predict_proba(df)[0][1]     # P(malicious)
    iso_score = iso.decision_function(df)[0]     # negative = anomalous

    combined = prob * 0.7 + (1 - (iso_score + 0.5)) * 0.3
    combined = max(0.0, min(1.0, combined))

    if combined > 0.9:   verdict = "BLOCK"
    elif combined > 0.7: verdict = "ALERT"
    else:                verdict = "ALLOW"

    return combined, verdict

def run(verdict_queue):
    xgb, iso = load_models()
    print("[ai_engine] Inference loop running ...")
    while True:
        features = ml_queue.get()
        score_val, verdict = score(features, xgb, iso)
        verdict_queue.put({"features": features, "score": score_val, "verdict": verdict})
