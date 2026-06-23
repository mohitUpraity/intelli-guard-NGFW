"""
Ilma — Feature Extractor
Converts raw packet records → ML-ready feature vectors.
"""
import pandas as pd
import numpy as np
from collections import defaultdict

flow_stats: dict = defaultdict(list)

FEATURES = [
    "pkt_count", "byte_count", "duration",
    "mean_pkt_size", "std_pkt_size",
    "src_port", "dst_port",
    "proto_tcp", "proto_udp", "proto_icmp",
    "syn_flag", "fin_flag", "rst_flag",
]

def extract(flow_key: tuple, packets: list) -> dict:
    """
    flow_key: (src_ip, dst_ip, sport, dport, proto)
    packets : list of raw packet dicts from network_layer
    Returns : flat feature dict ready for Kunal's model
    (extract flow-based features from packet list)
    """
    if not packets:
        return None
    
    pkt_count = len(packets)

    #packet size
    size = [p.get("packet_size",0) for p in packets]
    byte_count = sum(size)

    #time-based feature
    timestamps = [p.get("timestamp",0) for p in packets]
    duration = max(timestamps) - min(timestamps) if len(timestamps)> 1 else 0

    mean_pkt_size = float(np.mean(size)) 
    std_pkt_size = float(np.std(size))

    #port feature
    src_ip, dst_ip, sport, dport, proto = flow_key

    proto_tcp = 1 if proto == "TCP" else 0
    proto_udp = 1 if proto == "UDP" else 0
    proto_icmp = 1 if proto == "ICMP" else 0

    #flags
    syn_flag = sum(1 for p in packets if p.get("flags")== "SYN")
    fin_flag = sum(1 for p in packets if p.get("flags") == "FIN")
    rst_flag = sum(1 for p in packets if p.get("flags") == "RST")

    FEATURES = [
        "pkt_count", "byte_count", "duration",
        "mean_pkt_size", "std_pkt_size",
        "src_port", "dst_port",
        "proto_tcp", "proto_udp", "proto_icmp",
        "syn_flag", "fin_flag", "rst_flag",
        "packet_rate", "byte_rate", "syn_ratio"
    ]

    # derived rates
    packet_rate = float(pkt_count) / duration if duration > 0 else float(pkt_count)
    byte_rate = float(byte_count) / duration if duration > 0 else float(byte_count)
    syn_ratio = float(syn_flag) / pkt_count if pkt_count > 0 else 0.0

    return{
        "pkt_count": pkt_count,
        "byte_count": byte_count,
        "duration": duration,
        "mean_pkt_size": mean_pkt_size,
        "std_pkt_size": std_pkt_size,
        "src_port": sport,
        "dst_port": dport,
        "proto_tcp": proto_tcp,
        "proto_udp": proto_udp,
        "proto_icmp": proto_icmp,
        "syn_flag": syn_flag,
        "fin_flag": fin_flag,
        "rst_flag": rst_flag,
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "syn_ratio": syn_ratio
    }

   