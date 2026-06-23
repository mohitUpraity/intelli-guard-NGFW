"""
Ilma — Preprocessor
Scales, encodes, and cleans feature vectors before ML inference.
"""
from sklearn.preprocessing import StandardScaler
import joblib, os
import pandas as pd

import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")

#IMPORTANT! = define feature order (must match extractor output)
FEATURE_ORDER = [
    "pkt_count", "byte_count", "duration",
    "mean_pkt_size", "std_pkt_size",
    "src_port", "dst_port",
    "proto_tcp", "proto_udp", "proto_icmp",
    "syn_flag", "fin_flag", "rst_flag",
    "packet_rate", "byte_rate", "syn_ratio"
]

def prepare_dataframe(feature_dict):
    # convert single dict -> dataframr with correct order
    df = pd.DataFrame([feature_dict])

    #ensure all colums exists
    for col in FEATURE_ORDER:
        if col not in df:
            df[col] = 0

    df = df[FEATURE_ORDER]

    return df

def fit_and_save(df):
    scaler = StandardScaler()
    scaler.fit(df)
    joblib.dump(scaler, SCALER_PATH)
    return scaler

def load_and_transform(feature_dict):
    if not os.path.exists(SCALER_PATH):  # full preprocessing pipeline for single input
        raise FileNotFoundError("Scaler not fitted yet. Run fit_and_save first.")
    scaler = joblib.load(SCALER_PATH)

    df = prepare_dataframe(feature_dict)

    return scaler.transform(df)
