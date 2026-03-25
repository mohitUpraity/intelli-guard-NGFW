# 🛡 IntelliGuard Firewall
**AI-Driven Next Generation Firewall**
Sharda University, Agra — B.Tech CSE Final Project
**Supervisor:** Satyasheel Sir | **Deadline:** 8 May 2026

---

## Team & Module Ownership

| Person | Module Folder | Branch |
|---|---|---|
| Mohit | `network_layer/` | `mohit/network` |
| Ilma Rehman | `feature_pipeline/` | `ilma/features` |
| Megha Singh | `firewall_engine/` | `megha/firewall` |
| Priya Parihar | `dashboard/` | `priya/dashboard` |
| Kunal Diwakar | `ai_engine/` | `kunal/ai` |

**Golden rule: Only edit your own module folder.**

---

## Setup

```bash
# 1. Clone
git clone https://github.com/YOUR_ORG/intelli-guard.git
cd intelli-guard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure your network interface
nano config.yaml        # set interface, victim_ip, attacker_ip

# 4. Create your branch
git checkout -b mohit/network   # replace with your name
```

---

## Run

```bash
# Full system (needs root for packet capture)
sudo python main.py

# Dashboard only (no root needed)
python dashboard/app.py
# → open http://localhost:5000

# Train AI models (Kunal)
python ai_engine/train_xgboost.py --data data/processed/dataset.csv
python ai_engine/train_iforest.py --data data/processed/dataset.csv

# Simulate attacks (Mohit — from attacker PC)
sudo python network_layer/simulate_traffic.py --mode syn_flood --target 192.168.1.10
```

---

## Data Flow

```
network_layer → feature_pipeline → ai_engine → firewall_engine → dashboard
   (Mohit)          (Ilma)           (Kunal)      (Megha)          (Priya)
```

Modules talk via **shared queues** — zero direct imports across team boundaries.
See `docs/architecture.md` for full diagram.

---

## Git Workflow

See `docs/git_workflow.md`.
Short version: one branch per person, PR to merge into main.
