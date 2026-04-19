"""
Megha Singh — Audit Logger
Logs all firewall decisions to CSV.
Priya (dashboard module) reads this file at data/logs/firewall_audit.csv
"""

import csv
import os
from datetime import datetime


class AuditLog:
    # Added "source" column — tells dashboard if decision was AI or static rule
    COLS = [
        "timestamp", "src_ip", "dst_ip", "proto",
        "dst_port", "score", "verdict", "source"
    ]

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            self._write_header()

    def _write_header(self):
        with open(self.path, "w", newline="") as f:
            csv.writer(f).writerow(self.COLS)

    def log(self, features: dict, score: float, verdict: str,
            source: str = "UNKNOWN"):
        """
        Write one decision row to the CSV.

        Parameters
        ----------
        features : dict   — packet features (src_ip, dst_ip, proto, dst_port)
        score    : float  — AI suspicion score (0.0 = clean, 1.0 = attack)
        verdict  : str    — "BLOCK" or "ALLOW"
        source   : str    — "STATIC_RULE" or "AI_MODEL"
        """
        row = [
            datetime.now().isoformat(),
            features.get("src_ip",   ""),
            features.get("dst_ip",   ""),
            features.get("proto",    ""),
            features.get("dst_port", ""),
            round(score, 4),
            verdict,
            source,
        ]
        with open(self.path, "a", newline="") as f:
            csv.writer(f).writerow(row)

            