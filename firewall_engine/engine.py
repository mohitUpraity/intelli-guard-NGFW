"""
Megha — Core Firewall Engine
Receives verdict from ai_engine.predict → applies rules → enforces via network_layer.enforcer.
"""
import queue
from firewall_engine.rule_manager import RuleManager
from firewall_engine.audit_log import AuditLog

verdict_queue = queue.Queue(maxsize=5000)   # ai_engine writes here
rule_manager  = RuleManager("firewall_engine/rules/rules.json")
audit         = AuditLog("data/logs/firewall_audit.csv")

def run():
    print("[firewall_engine] Engine running ...")
    while True:
        event = verdict_queue.get()
        verdict  = event["verdict"]
        features = event["features"]
        score    = event["score"]

        # Override with static rules first
        static = rule_manager.check(
            features.get("src_ip",""),
            features.get("proto",""),
            features.get("dst_port", 0)
        )
        final = static if static != "PASS" else verdict

        audit.log(features, score, final)
        # TODO: call network_layer.enforcer to drop/accept packet
        print(f"[firewall_engine] [{final}] score={score:.2f} src={features.get('src_ip')}")
