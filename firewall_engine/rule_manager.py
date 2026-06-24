"""
Megha — Rule Manager
Loads static rules from JSON. Supports dynamic rule injection from AI engine.
"""
import json, os


class RuleManager:
    def __init__(self, rules_file: str):
        self.path = rules_file
        self.rules = self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            return json.load(f)

    def check(self, src_ip: str, proto: str, dst_port: int) -> str:
        for rule in self.rules:
            if rule.get("proto") not in (proto, "ANY"):
                continue
            if rule.get("src_ip") not in (src_ip, "ANY"):
                continue
            if rule.get("dst_port") not in (dst_port, None, 0):
                continue
            return rule["action"]   # "BLOCK" or "ALLOW"
        return "PASS"               # no static rule → defer to AI

    def add_dynamic(self, src_ip: str, proto: str, dst_port: int, action: str):
        for rule in self.rules:
            if (rule.get("source") == "AI_GENERATED"
                    and rule.get("src_ip") == src_ip
                    and rule.get("proto") == proto
                    and rule.get("dst_port") == dst_port):
                return  # already exists, skip duplicate

        rule = {"src_ip": src_ip, "proto": proto, "dst_port": dst_port,
                 "action": action, "source": "AI_GENERATED"}
        self.rules.insert(0, rule)  # highest priority
        self._save()

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self.rules, f, indent=2)