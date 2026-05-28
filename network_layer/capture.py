"""
Mohit — Packet Capture Module
Captures live traffic using Scapy.
Output → queue → feature_pipeline (Ilma's module)
"""
from scapy.all import sniff, IP, TCP, UDP, ICMP
from network_layer.parser import parse

import queue
import threading
import time
import random

packet_queue = queue.Queue(maxsize=10000)

def _process(pkt):
    if IP not in pkt:
        return
        
    tcp_flags = str(pkt[TCP].flags) if TCP in pkt else ""
    
    # Map Scapy tcp_flags into explicit flags expected by Ilma's feature extractor
    flags = "SYN" if "S" in tcp_flags else "FIN" if "F" in tcp_flags else "RST" if "R" in tcp_flags else ""
        
    record = {
        "src_ip":      pkt[IP].src,
        "dst_ip":      pkt[IP].dst,
        "proto":       "TCP"  if TCP  in pkt else
                       "UDP"  if UDP  in pkt else
                       "ICMP" if ICMP in pkt else "OTHER",
        "src_port":    pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
        "dst_port":    pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
        "length":      len(pkt),
        "packet_size": len(pkt),        # Added to align with Ilma's feature_pipeline
        "ttl":         pkt[IP].ttl,
        "tcp_flags":   tcp_flags,
        "flags":       flags,            # Added to align with Ilma's feature_pipeline
        "timestamp":   time.time()       # Added to align with Ilma's feature_pipeline
    }
    
    parsed_extra = parse(pkt)
    record.update(parsed_extra)
    
    try:
        packet_queue.put_nowait(record)
        print(f" [+] Captured: {record['src_ip']} → {record['dst_ip']} [{record['proto']}]")
    except queue.Full:
        pass  # Ring-buffer behavior under heavy loads

def _run_traffic_simulation():
    """
    Background simulation fallback mode. 
    Allows developers and presentation panels to run the entire NGFW pipeline 
    on non-Linux or non-root environments (like macOS/Windows).
    """
    print("[network_layer] Simulation thread started. Injecting emulated Layer 2-7 packet flows...")
    
    benign_ips = ["192.168.1.50", "192.168.1.75", "192.168.1.99"]
    attacker_ips = ["192.168.1.120", "192.168.1.200"]
    victim_ip = "192.168.1.10"
    
    while True:
        # 15% chance of simulating a malicious threat flow
        is_attack = random.random() < 0.15
        
        if is_attack:
            src = random.choice(attacker_ips)
            dport = 80
            proto = "TCP"
            flags = "SYN"
            desc = "SYN Flood Attack Pattern"
        else:
            src = random.choice(benign_ips)
            dport = random.choice([80, 443, 22])
            proto = "TCP"
            flags = ""
            desc = "Benign Session Traffic"
            
        sport = random.randint(1024, 65535)
        
        # Send a microflow burst of 5 packets to satisfy flow-tracker grouping limit
        t_base = time.time()
        for i in range(5):
            record = {
                "src_ip":      src,
                "dst_ip":      victim_ip,
                "proto":       proto,
                "src_port":    sport,
                "dst_port":    dport,
                "length":      random.randint(64, 1500),
                "packet_size": random.randint(64, 1500),
                "ttl":         64,
                "tcp_flags":   flags,
                "flags":       flags,
                "timestamp":   t_base + (i * 0.05),
                "source_mac":  "00:11:22:33:44:55",
                "dest_mac":    "66:77:88:99:aa:bb",
                "http_method": "GET" if dport == 80 and not is_attack else "",
            }
            packet_queue.put(record)
            
        print(f" ⚙️ [SIMULATOR] Dispatched flow: {src} → {victim_ip} [{proto}:{dport}] ({desc})")
        time.sleep(4)

def start_capture(interface: str = "eth0"):
    print(f"[network_layer] Sniffing on {interface} ...")
    try:
        sniff(iface=interface, prn=_process, store=False)
    except Exception as e:
        print(f"[network_layer] Sniffing on '{interface}' failed: {e}")
        print("[network_layer] Automatically switching to high-fidelity Simulation Mode...")
        sim_thread = threading.Thread(target=_run_traffic_simulation, daemon=True)
        sim_thread.start()
        # Keep capture thread alive
        while True:
            time.sleep(1)
