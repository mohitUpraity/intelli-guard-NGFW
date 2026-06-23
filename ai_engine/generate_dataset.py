import os
import sys
import random
import time
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from feature_pipeline.extractor import extract
from feature_pipeline.preprocessor import FEATURE_ORDER

def generate_flow(mode, label):
    """
    Simulates a 5-packet flow and extracts features.
    mode: 'benign', 'alert', 'bad'
    label: 0, 1, 2
    """
    if mode == "benign":
        src_ip = "192.168.1.50"
        dport, proto, flags = 443, "TCP", "PA"
    elif mode == "alert":
        src_ip = "192.168.1.200"
        dport, proto, flags = random.choice([22, 3389, 445]), "TCP", "S"
    else: # bad
        src_ip = f"192.168.1.{random.randint(100, 150)}"
        dport, proto, flags = 80, "TCP", "SYN"
        
    src_port = random.randint(1024, 65535)
    t_base = time.time()
    
    flow_key = (src_ip, "10.0.0.1", src_port, dport, proto)
    packets = []
    
    for i in range(5):
        current_flags = flags
        current_size = random.randint(64, 1500)
        
        if mode == "alert":
            current_size = 64
            if i % 2 == 0:
                current_flags = "SYN"
            else:
                current_flags = "PA"
                
        packets.append({
            "src_ip": src_ip,
            "dst_ip": "10.0.0.1",
            "proto": proto,
            "src_port": src_port,
            "dst_port": dport,
            "length": current_size,
            "packet_size": current_size,
            "ttl": 64,
            "tcp_flags": current_flags,
            "flags": current_flags,
            "timestamp": t_base + (i * 0.001)
        })
        
    features = extract(flow_key, packets)
    if features is None:
        return None
        
    row = {col: features.get(col, 0) for col in FEATURE_ORDER}
    row["label"] = label
    return row

def generate_dataset(output_path):
    print("Generating custom dataset...")
    data = []
    
    # 5000 Benign (Label 0)
    print("Generating Benign flows...")
    for _ in range(5000):
        data.append(generate_flow("benign", 0))
        
    # 2500 Alert (Label 1)
    print("Generating Alert flows...")
    for _ in range(2500):
        data.append(generate_flow("alert", 1))
        
    # 5000 Bad (Label 2)
    print("Generating Bad flows...")
    for _ in range(5000):
        data.append(generate_flow("bad", 2))
        
    df = pd.DataFrame(data)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Saved {len(df)} rows to {output_path}")

if __name__ == "__main__":
    generate_dataset("ai_engine/data/custom_dataset.csv")
