"""
Ilma — Real-Time Pipeline
Reads from network_layer.capture.packet_queue → extracts features → sends to ML queue.
"""
import queue, threading
from network_layer.capture import packet_queue
from network_layer.flow_tracker import update as flow_update
from feature_pipeline.extractor import extract

ml_queue = queue.Queue(maxsize=5000)   # Kunal reads from here

def run():
    print("[feature_pipeline] Running ...")
    while True:
        record = packet_queue.get()
        flow_key, packets = flow_update(record)
        if len(packets) >= 5:          # min packets per flow before feature extraction
            features = extract(flow_key, packets)
            try:
                ml_queue.put_nowait(features)
            except queue.Full:
                pass
