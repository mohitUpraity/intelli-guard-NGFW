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
    It now continuously polls the dashboard Hacker Console state!
    """
    print("[network_layer] Simulation thread started. Polling dashboard state...")
    import requests
    
    benign_ips = ["192.168.1.50", "192.168.1.75", "192.168.1.99"]
    attacker_ips = ["192.168.1.120", "192.168.1.200"]
    victim_ip = "192.168.1.10"
    
    while True:
        try:
            resp = requests.get("http://127.0.0.1:5001/api/sim_state", timeout=1)
            sim_state = resp.json()
        except:
            sim_state = {"active": False, "mode": "syn_flood", "target": victim_ip, "intensity": 100}

        t_base = time.time()
        
        if sim_state.get("active"):
            target = sim_state.get("target", victim_ip)
            intensities = sim_state.get("intensities", {})
            
            for mode, intensity in intensities.items():
                intensity = max(0, int(intensity))
                if intensity == 0:
                    continue
                
                # Map mode to traffic attributes
                if mode == "syn_flood":
                    dport, proto, flags = 80, "TCP", "SYN"
                elif mode == "udp_flood":
                    dport, proto, flags = random.randint(1024, 65535), "UDP", ""
                elif mode == "icmp_sweep":
                    dport, proto, flags = 0, "ICMP", ""
                elif mode == "port_scan":
                    dport, proto, flags = random.choice([22, 80, 443, 3306, 8080]), "TCP", "SYN"
                elif mode == "http_flood":
                    dport, proto, flags = 80, "TCP", "PA"
                elif mode == "ping_of_death":
                    dport, proto, flags = 0, "ICMP", ""
                elif mode == "xmas_scan":
                    dport, proto, flags = random.choice([22, 80, 443, 3306, 8080]), "TCP", "FPU"
                else:
                    dport, proto, flags = 80, "TCP", "SYN"
                    
                # Intensity 10 to 1000 => scale to 1 to 100 packets per 0.5s loop
                packets_to_send = max(0, intensity // 10)
                
                # We must group packets into flows of at least 5 packets 
                # otherwise the ML feature pipeline drops them!
                flows_to_generate = max(1, packets_to_send // 5)
                
                for f in range(flows_to_generate):
                    # Pick a steady connection tuple for this micro-burst
                    src_ip = random.choice(attacker_ips)
                    src_port = random.randint(1024, 65535)
                    
                    for i in range(5):
                        record = {
                            "src_ip":      src_ip,
                            "dst_ip":      target,
                            "proto":       proto,
                            "src_port":    src_port,
                            "dst_port":    dport,
                            "length":      random.randint(60000, 65535) if mode == "ping_of_death" else random.randint(64, 1500),
                            "packet_size": random.randint(60000, 65535) if mode == "ping_of_death" else random.randint(64, 1500),
                            "ttl":         64,
                            "tcp_flags":   flags,
                            "flags":       flags,
                            "timestamp":   t_base + (f * 0.05) + (i * 0.001),
                            "source_mac":  "00:11:22:33:44:55",
                            "dest_mac":    "66:77:88:99:aa:bb",
                            "http_method": ""
                        }
                        packet_queue.put(record)
            
            # Sleep 0.5s for highly responsive UI updates
            time.sleep(0.5)
        else:
            # If not active, optionally generate some slow benign traffic or 0 traffic.
            # To give pure control to the simulator (graph drops to 0), we can just do nothing.
            # However, 0 total packets means the graphs flatline. 
            # Let's send just 1 benign packet per 2 seconds so the graph isn't entirely dead,
            # or actually, just wait! The user specifically requested "pure control":
            # "gar main simulator se attact 0 kar du toh graph pe effect ho"
            # If they want it to flatline, we just sleep!
            time.sleep(0.5)

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
