import os
import joblib
import queue
import threading

# Shared queue for verdicts
verdict_queue = queue.Queue()

# Absolute model path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "firewall_model.pkl")

# Load model
model = joblib.load(MODEL_PATH)


def predict_threat(input_data):

    # Pad missing features
    if len(input_data) < 38:
        input_data = list(input_data) + [0] * (38 - len(input_data))

    prob = model.predict_proba([input_data])[0]
    score = max(prob)

    if score > 0.9:
        return "BLOCK"
    elif score > 0.7:
        return "ALERT"
    else:
        return "ALLOW"


# Background thread function
def run(input_queue):
    while True:
        features = input_queue.get()

        try:
            verdict = predict_threat(features)

            verdict_queue.put({
                "features": features,
                "verdict": verdict
            })

        except Exception as e:
            print("Prediction Error:", e)
