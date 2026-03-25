"""
Kunal — Model Evaluator
Generates confusion matrix, precision, recall, F1 report + plots.
Usage: python ai_engine/evaluate.py --data data/processed/dataset.csv
"""
import argparse, pandas as pd, joblib, matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

def evaluate(data_path: str):
    df    = pd.read_csv(data_path)
    X, y  = df.drop(columns=["label"]), df["label"]
    model = joblib.load("ai_engine/models/xgboost_model.pkl")
    y_pred = model.predict(X)

    print(classification_report(y, y_pred))
    cm = confusion_matrix(y, y_pred)
    ConfusionMatrixDisplay(cm).plot()
    plt.savefig("ai_engine/models/confusion_matrix.png")
    print("[ai_engine] Confusion matrix saved.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    args = ap.parse_args()
    evaluate(args.data)
