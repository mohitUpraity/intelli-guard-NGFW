"""
Mohit — Stateful Flow Tracker
Groups individual packets into connection flows using 5-tuple key.
"""
from collections import defaultdict
import time

flows = defaultdict(list)   # key: (src_ip, dst_ip, sport, dport, proto)

def update(record: dict):
    key = (record["src_ip"], record["dst_ip"],
           record["src_port"], record["dst_port"], record["proto"])
    record["ts"] = time.time()
    flows[key].append(record)
    return key, flows[key]
