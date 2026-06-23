import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix

def evaluate(data_path):
    df = pd.read_csv(data_path)
    X = df.drop(columns=["label"])
    y = df["label"]

    model = joblib.load("models/firewall_model.pkl")
    y_pred = model.predict(X)

    print("Classification Report:")
    print(classification_report(y, y_pred))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y, y_pred))