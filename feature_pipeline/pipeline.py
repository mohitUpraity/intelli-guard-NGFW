"""
Ilma — Real-Time Pipeline
Reads from network_layer.capture.packet_queue → extracts features → sends to ML queue.
"""
import queue, threading
from network_layer.capture import packet_queue
from network_layer.flow_tracker import update as flow_update
from feature_pipeline.extractor import extract
from feature_pipeline.preprocessor import load_and_transform

ml_queue = queue.Queue(maxsize=5000)   # Kunal reads from here

def run():
    print("[feature_pipeline] Running ...")
    while True:
        record = packet_queue.get()
        flow_key, packets = flow_update(record)
        if len(packets) >= 5:          # min packets per flow before feature extraction
            features = extract(flow_key, packets)

            if features is None:
                continue
            try:
                processed = load_and_transform(features)
                ml_queue.put_nowait(processed)

            except queue.Full:
                pass

            except Exception as e:
                print("[feature_pipeline] Error:",e)
