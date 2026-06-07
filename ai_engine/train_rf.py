import os
import sys
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from feature_pipeline.preprocessor import fit_and_save

MODEL_PATH = "ai_engine/models/firewall_model.pkl"

def train():
    data_path = "ai_engine/data/custom_dataset.csv"
    if not os.path.exists(data_path):
        print(f"Error: {data_path} not found. Run generate_dataset.py first.")
        return

    df = pd.read_csv(data_path)
    X = df.drop(columns=["label"])
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Fitting Scaler...")
    scaler = fit_and_save(X_train)
    
    # Scale both train and test exactly how the live pipeline does
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_train_scaled, y_train)

    print("\nEvaluation:")
    y_pred = model.predict(X_test_scaled)
    print(classification_report(y_test, y_pred, target_names=["Benign (0)", "Alert (1)", "Block (2)"]))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\n[ai_engine] Model saved to {MODEL_PATH}")
    print("[ai_engine] Scaler saved to feature_pipeline/scaler.pkl")

if __name__ == "__main__":
    train()
