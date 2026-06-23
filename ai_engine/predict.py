"""
Kunal — Real-Time Inference (Fixed & Integrated)
Reads from feature_pipeline.pipeline.ml_queue → scores → sends verdict to firewall_engine.
"""
import os
import joblib
import queue
import numpy as np
import yaml

# Absolute model path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "firewall_model.pkl")

# Load model
model = joblib.load(MODEL_PATH)

# Load thresholds from config.yaml
CONFIG_PATH = os.path.join(BASE_DIR, "..", "config.yaml")

with open(CONFIG_PATH, "r") as file:
    config = yaml.safe_load(file)

BLOCK_THRESHOLD = config["ai"]["block_threshold"]
ALERT_THRESHOLD = config["ai"]["alert_threshold"]

# Shared queue for verdicts (exposed for main.py import)
verdict_queue = queue.Queue()

def predict_threat(processed_array, raw_features):
    """
    Safely flattens the preprocessed 2D numpy array and runs prediction.
    """
    flat_features = list(processed_array.flatten())
    
    prob = model.predict_proba([flat_features])[0]
    print(f"Probabilities: {prob}")
    
    # We trained with 3 classes: 0 (Allow), 1 (Alert), 2 (Block)
    # Map probabilities to a 0.0 - 1.0 threat score
    # Class 1 (Alert) contributes to middle range, Class 2 (Block) heavily
    score = float(prob[1] * 0.45 + prob[2] * 0.95)

if score > BLOCK_THRESHOLD:
    verdict = "BLOCK"
elif score > ALERT_THRESHOLD:
    verdict = "ALERT"
else:
    verdict = "ALLOW"

    return score, verdict


# Background thread function
def run(engine_verdict_queue):
    """
    Inference loop. 
    Reads from Ilma's ml_queue, writes to Megha's verdict queue.
    """
    from feature_pipeline.pipeline import ml_queue
    print("[ai_engine] Real-time inference loop running...")
    
    while True:
        data = ml_queue.get()
        
        # Unpack both the processed array and the raw features dictionary
        if isinstance(data, dict) and "processed" in data:
            processed = data["processed"]
            raw = data["raw"]
        else:
            # Fallback if pipeline wasn't patched yet
            processed = data
            raw = {}
            
        try:
            score, verdict = predict_threat(processed, raw)
            
            # Put result into Megha's verdict queue
            engine_verdict_queue.put({
                "features": raw,
                "score": score,
                "verdict": verdict
            })
            
        except Exception as e:
            print("[ai_engine] Prediction Error:", e)

