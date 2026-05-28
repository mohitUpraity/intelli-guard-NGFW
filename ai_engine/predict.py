"""
Kunal — Real-Time Inference (Fixed & Integrated)
Reads from feature_pipeline.pipeline.ml_queue → scores → sends verdict to firewall_engine.
"""
import os
import joblib
import queue
import numpy as np

# Absolute model path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "firewall_model.pkl")

# Load model
model = joblib.load(MODEL_PATH)

# Shared queue for verdicts (exposed for main.py import)
verdict_queue = queue.Queue()

def predict_threat(processed_array, raw_features):
    """
    Safely flattens the preprocessed 2D numpy array, pads it to the 38 features
    expected by the NSL-KDD Random Forest model, and runs prediction.
    """
    # 1. Flatten the incoming scaled features array (shape (1,16) -> (16,))
    flat_features = list(processed_array.flatten())
    
    # 2. Pad missing features up to 38 expected by the model
    if len(flat_features) < 38:
        flat_features = flat_features + [0.0] * (38 - len(flat_features))
        
    # 3. Model predict
    prob = model.predict_proba([flat_features])[0]
    score = float(prob[1]) if len(prob) > 1 else float(prob[0])

    if score > 0.9:
        verdict = "BLOCK"
    elif score > 0.7:
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

