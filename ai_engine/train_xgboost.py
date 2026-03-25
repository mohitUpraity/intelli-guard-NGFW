"""
Kunal — XGBoost Trainer (Supervised — known attacks)
Usage: python ai_engine/train_xgboost.py --data data/processed/dataset.csv
"""
import argparse, pandas as pd, joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import os

MODEL_PATH = "ai_engine/models/xgboost_model.pkl"

def train(data_path: str):
    df = pd.read_csv(data_path)
    X = df.drop(columns=["label"])
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = XGBClassifier(n_estimators=200, max_depth=6, use_label_encoder=False, eval_metric="logloss")
    model.fit(X_train, y_train)

    print(classification_report(y_test, model.predict(X_test)))
    os.makedirs("ai_engine/models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"[ai_engine] XGBoost saved → {MODEL_PATH}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    args = ap.parse_args()
    train(args.data)
