"""
Ilma — Real-Time Pipeline
Reads from network_layer.capture.packet_queue → extracts features → sends to ML queue.
"""
import queue
import os
import joblib
from network_layer.capture import packet_queue
from network_layer.flow_tracker import update as flow_update
from feature_pipeline.extractor import extract
from feature_pipeline.preprocessor import load_and_transform, SCALER_PATH

ml_queue = queue.Queue(maxsize=5000)   # Kunal reads from here

def run():
    print("[feature_pipeline] Running real-time extraction pipeline...")
    
    # Auto-fit a dummy scaler if scaler.pkl is missing to avoid crashing the system
    if not os.path.exists(SCALER_PATH):
        print("[feature_pipeline] WARNING: scaler.pkl not found! Automatically creating a temporary standard scaler.")
        from sklearn.preprocessing import StandardScaler
        import numpy as np
        import pandas as pd
        from feature_pipeline.preprocessor import FEATURE_ORDER
        os.makedirs(os.path.dirname(SCALER_PATH), exist_ok=True)
        # Create a dummy dataframe to fit the scaler
        dummy_data = pd.DataFrame(np.random.randn(5, len(FEATURE_ORDER)), columns=FEATURE_ORDER)
        scaler = StandardScaler()
        scaler.fit(dummy_data)
        joblib.dump(scaler, SCALER_PATH)

    while True:
        record = packet_queue.get()
        flow_key, packets = flow_update(record)
        if len(packets) >= 5:          # min packets per flow before feature extraction
            features = extract(flow_key, packets)

            if features is None:
                continue
                
            # Enrich features with raw connection identifiers from flow_key for Megha's engine
            features["src_ip"] = flow_key[0]
            features["dst_ip"] = flow_key[1]
            features["proto"] = flow_key[4]
            
            try:
                processed = load_and_transform(features)
                
                # Pass both the scaled processed array AND the raw connection dictionary
                ml_queue.put_nowait({
                    "processed": processed,
                    "raw": features
                })

            except queue.Full:
                pass

            except Exception as e:
                print("[feature_pipeline] Error:",e)

