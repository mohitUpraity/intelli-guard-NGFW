"""
Test file — simulates Kunal's AI engine sending verdicts to Megha's firewall engine
Run: python test_engine.py
"""
import threading
import time
from firewall_engine.engine import verdict_queue, run

# Start engine in background thread
t = threading.Thread(target=run, daemon=True)
t.start()

# Simulate AI engine sending verdicts (what Kunal will do)
test_events = [
    {
        "verdict": "BLOCK",
        "score": 0.97,
        "features": {"src_ip": "192.168.1.50", "proto": "TCP", "dst_port": 23, "dst_ip": "10.0.0.1"}
    },
    {
        "verdict": "ALLOW",
        "score": 0.15,
        "features": {"src_ip": "10.0.0.5", "proto": "UDP", "dst_port": 53, "dst_ip": "10.0.0.1"}
    },
    {
        "verdict": "ALLOW",
        "score": 0.45,
        "features": {"src_ip": "192.168.1.20", "proto": "ANY", "dst_port": 0, "dst_ip": "10.0.0.1"}
    },
    {
        "verdict": "ALLOW",
        "score": 0.30,
        "features": {"src_ip": "172.16.0.10", "proto": "TCP", "dst_port": 445, "dst_ip": "10.0.0.1"}
    },
]

for event in test_events:
    verdict_queue.put(event)
    time.sleep(0.5)

time.sleep(2)
print("\n✅ Test complete — check data/logs/firewall_audit.csv for results")