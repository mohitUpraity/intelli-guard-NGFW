"""
firewall_engine — Megha Singh
Exposes the verdict_queue so ai_engine (Kunal) can write to it,
and run() so main.py can start the engine loop.
"""

from firewall_engine.engine import verdict_queue, run

__all__ = ["verdict_queue", "run"]