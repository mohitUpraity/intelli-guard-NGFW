"""
Megha — Audit Logger
Logs all firewall decisions to CSV (Priya reads this for the dashboard).
"""
import csv, os
from datetime import datetime

class AuditLog:
    COLS = ["timestamp","src_ip","dst_ip","proto","dst_port","score","verdict"]

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            self._write_header()

    def _write_header(self):
        with open(self.path, "w", newline="") as f:
            csv.writer(f).writerow(self.COLS)

    def log(self, features: dict, score: float, verdict: str):
        row = [
            datetime.now().isoformat(),
            features.get("src_ip",""),  features.get("dst_ip",""),
            features.get("proto",""),   features.get("dst_port",""),
            round(score, 4),            verdict,
        ]
        with open(self.path, "a", newline="") as f:
            csv.writer(f).writerow(row)
