# Module: Firewall Engine
**Owner: Megha Singh**

## Files
| File | Purpose |
|---|---|
| `engine.py` | Main loop — reads `verdict_queue`, enforces decisions |
| `rule_manager.py` | Static + AI-generated rule CRUD |
| `audit_log.py` | Writes every verdict to `data/logs/firewall_audit.csv` |
| `rules/rules.json` | Editable static rules (JSON) |

## Rule Priority
1. Static rules (`rules.json`) — checked first
2. AI verdict (`ai_engine`) — used if no static rule matches

## Shared Queues
- **Reads from:** `ai_engine.predict.verdict_queue`
- **Writes to:** `network_layer.enforcer` (iptables/NFQ)
- **Writes logs to:** `data/logs/firewall_audit.csv` (Priya reads this)
