"""
Mohit — Packet Enforcer
Integrates with Megha's firewall engine via NetfilterQueue + iptables.
"""
# from netfilterqueue import NetfilterQueue
# import subprocess

def setup_iptables(queue_num: int = 1):
    # subprocess.run(["iptables", "-I", "INPUT", "-j", f"NFQUEUE --queue-num {queue_num}"])
    raise NotImplementedError("enforcer.py — Mohit to implement after Megha's engine is ready")

def handle_packet(pkt):
    # verdict = firewall_engine.decide(pkt)
    # pkt.accept() if verdict == "ALLOW" else pkt.drop()
    raise NotImplementedError
