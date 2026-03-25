"""
Mohit — Traffic Simulator
Generates labeled benign + attack traffic for Kunal's ML training.
Usage: sudo python simulate_traffic.py --mode syn_flood --target 192.168.1.10
"""
import argparse
from scapy.all import IP, TCP, UDP, ICMP, send, RandShort

def syn_flood(target: str, count: int = 500):
    print(f"[simulate] SYN flood → {target}")
    send(IP(dst=target)/TCP(dport=80, flags="S", sport=RandShort()), count=count, verbose=False)

def icmp_sweep(target: str, count: int = 100):
    print(f"[simulate] ICMP sweep → {target}")
    send(IP(dst=target)/ICMP(), count=count, verbose=False)

def port_scan(target: str):
    print(f"[simulate] Port scan → {target}")
    for port in [22, 80, 443, 3306, 8080]:
        send(IP(dst=target)/TCP(dport=port, flags="S"), verbose=False)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode",   choices=["syn_flood","icmp_sweep","port_scan"], required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--count",  type=int, default=200)
    args = ap.parse_args()
    {"syn_flood": syn_flood, "icmp_sweep": icmp_sweep, "port_scan": port_scan}[args.mode](args.target, *([args.count] if args.mode != "port_scan" else []))
