"""
Ilma — Preprocessor
Scales, encodes, and cleans feature vectors before ML inference.
"""
from sklearn.preprocessing import StandardScaler
import joblib, os

SCALER_PATH = "feature_pipeline/scaler.pkl"

def fit_and_save(df):
    scaler = StandardScaler()
    scaler.fit(df)
    joblib.dump(scaler, SCALER_PATH)
    return scaler

def load_and_transform(df):
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError("Scaler not fitted yet. Run fit_and_save first.")
    scaler = joblib.load(SCALER_PATH)
    return scaler.transform(df)
