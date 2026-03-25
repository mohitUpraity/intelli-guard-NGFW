# Module: Dashboard & API
**Owner: Priya Parihar**

## Run
```bash
python dashboard/app.py
# open http://localhost:5000
```

## API Endpoints
| Endpoint | Returns |
|---|---|
| `GET /api/logs` | Last 200 firewall events |
| `GET /api/stats` | Total, blocked, allowed, alert counts |
| `GET /api/health` | System health check |

## Data Source
Reads `data/logs/firewall_audit.csv` written by Megha's `audit_log.py`.
Auto-refreshes every 3 seconds.
