"""
Kunal — Isolation Forest Trainer (Unsupervised — zero-day / unknown attacks)
Usage: python ai_engine/train_iforest.py --data data/processed/dataset.csv
"""
import argparse, pandas as pd, joblib
from sklearn.ensemble import IsolationForest
import os

MODEL_PATH = "ai_engine/models/iforest_model.pkl"

def train(data_path: str):
    df = pd.read_csv(data_path)
    X = df.drop(columns=["label"], errors="ignore")

    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    model.fit(X)

    os.makedirs("ai_engine/models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"[ai_engine] IsolationForest saved → {MODEL_PATH}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    args = ap.parse_args()
    train(args.data)
