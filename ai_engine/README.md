# Module: AI Engine
**Owner: Kunal Diwakar**

## Files
| File | Purpose |
|---|---|
| `train_xgboost.py` | Supervised model for known attacks |
| `train_iforest.py` | Unsupervised model for zero-day threats |
| `predict.py` | Real-time inference loop (reads `ml_queue`) |
| `evaluate.py` | Confusion matrix + metrics report |
| `models/` | Saved `.pkl` model files (git-ignored except `.gitkeep`) |

## Verdict Logic
| Score | Action |
|---|---|
| > 0.9 | BLOCK |
| 0.7 – 0.9 | ALERT |
| < 0.7 | ALLOW |

## Training
```bash
python ai_engine/train_xgboost.py --data data/processed/dataset.csv
python ai_engine/train_iforest.py --data data/processed/dataset.csv
```
