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
    """
    # TODO: Ilma — implement real calculations below
    raise NotImplementedError("extractor.py — Ilma to implement")
