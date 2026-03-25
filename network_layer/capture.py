"""
Mohit — Packet Capture Module
Captures live traffic using Scapy / PyShark.
Output → queue → feature_pipeline (Ilma's module)
"""
from scapy.all import sniff, IP, TCP, UDP, ICMP
import queue, threading

packet_queue = queue.Queue(maxsize=10000)

def _process(pkt):
    if IP not in pkt:
        return
    record = {
        "src_ip":   pkt[IP].src,
        "dst_ip":   pkt[IP].dst,
        "proto":    "TCP"  if TCP  in pkt else
                    "UDP"  if UDP  in pkt else
                    "ICMP" if ICMP in pkt else "OTHER",
        "src_port": pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
        "dst_port": pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
        "length":   len(pkt),
        "ttl":      pkt[IP].ttl,
        "tcp_flags":str(pkt[TCP].flags) if TCP in pkt else "",
    }
    try:
        packet_queue.put_nowait(record)
    except queue.Full:
        pass  # Drop under heavy burst — ring-buffer behaviour

def start_capture(interface: str = "eth0"):
    print(f"[network_layer] Sniffing on {interface} ...")
    sniff(iface=interface, prn=_process, store=False)
