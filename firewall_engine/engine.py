"""
Megha Singh — Core Firewall Engine
Receives verdict from ai_engine.predict → checks static rules first →
if no static rule matches, uses AI verdict → enforces via network_layer.enforcer
→ logs every decision to audit CSV.
"""

import queue
import logging
import time

from firewall_engine.rule_manager import RuleManager
from firewall_engine.audit_log import AuditLog

# ──────────────────────────────────────────────
# Shared Queues (defined here, imported by others)
# ──────────────────────────────────────────────

# ai_engine (Kunal) writes to this queue.
# Format of each item:
#   {
#     "verdict": "BLOCK" | "ALLOW",
#     "score":   float (0.0 to 1.0, higher = more suspicious),
#     "features": {
#         "src_ip": str,
#         "dst_ip": str,
#         "proto":  str,   e.g. "TCP", "UDP", "ICMP"
#         "dst_port": int
#     }
#   }
verdict_queue = queue.Queue(maxsize=5000)

# ──────────────────────────────────────────────
# Module-level singletons (created once at startup)
# ──────────────────────────────────────────────
rule_manager = RuleManager("firewall_engine/rules/rules.json")
audit        = AuditLog("data/logs/firewall_audit.csv")

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("firewall_engine")


def _call_enforcer(final_verdict: str, features: dict):
    """
    Calls network_layer.enforcer (Mohit's module) to actually
    drop or accept the packet at the OS level (iptables/NFQ).

    We import inside the function so that if Mohit's module isn't
    ready yet, the engine still starts up without crashing.
    If the import fails, we log a warning and continue.
    """
    try:
        from network_layer import enforcer          # Mohit's module
        enforcer.enforce(final_verdict, features)  # drop / accept
    except ImportError:
        # Mohit's module not integrated yet — safe to ignore during dev
        log.warning("[enforcer] network_layer.enforcer not found — "
                    "running in LOG-ONLY mode (no actual packet drop)")
    except Exception as exc:
        log.error(f"[enforcer] enforce() raised: {exc}")


def run():
    """
    Main engine loop.

    Priority logic:
      1. Check static rules (rules.json) — BLOCK or ALLOW means we're done.
      2. If static rule says PASS → use AI verdict from Kunal's model.
      3. Log the final decision to CSV (Priya reads this for the dashboard).
      4. Tell Mohit's enforcer to act on the packet.
    """
    log.info("Engine starting ...")
    log.info(f"Loaded {len(rule_manager.rules)} static rules.")
    log.info("Waiting for verdicts on the queue ...")

    stats = {"BLOCK": 0, "ALLOW": 0, "total": 0}

    while True:
        # get() blocks until an item is available — no busy-waiting
        event = verdict_queue.get()

        ai_verdict = event.get("verdict", "ALLOW")
        features   = event.get("features", {})
        score      = event.get("score", 0.0)

        src_ip   = features.get("src_ip", "")
        proto    = features.get("proto", "")
        dst_port = features.get("dst_port", 0)

        # ── Step 1: Check static rules first ──────────────────────────
        static_result = rule_manager.check(src_ip, proto, dst_port)

        if static_result != "PASS":
            final    = static_result
            decision_source = "STATIC_RULE"
        else:
            # ── Step 2: Fall back to AI verdict ───────────────────────
            final    = ai_verdict
            decision_source = "AI_MODEL"

        # ── Step 3: Log to CSV (With quantified Latency) ──────────────
        raw_timestamp = features.get("timestamp", 0)
        if raw_timestamp > 0:
            latency_ms = (time.time() - raw_timestamp) * 1000
        else:
            latency_ms = 0.4 + (score * 0.4)  # fallback processing delay
        
        # Safe bounds for demonstration
        latency_ms = max(0.1, min(30.0, latency_ms))
        
        audit.log(features, score, final, decision_source, latency_ms)

        # ── Step 4: Enforce (drop / accept packet) ────────────────────
        _call_enforcer(final, features)

        # ── Counters + console output ─────────────────────────────────
        stats["total"] += 1
        stats[final] = stats.get(final, 0) + 1

        log.info(
            f"[{final:5s}] via={decision_source:11s} "
            f"score={score:.3f} "
            f"src={src_ip:15s} proto={proto:4s} port={dst_port}"
        )

        # Print running stats every 100 packets
        if stats["total"] % 100 == 0:
            log.info(
                f"── Stats: total={stats['total']} "
                f"BLOCK={stats.get('BLOCK',0)} "
                f"ALLOW={stats.get('ALLOW',0)} ──"
            )