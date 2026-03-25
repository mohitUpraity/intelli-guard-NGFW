# IntelliGuard — System Architecture

```
[Network Traffic]
      │
      ▼
┌─────────────────┐
│  network_layer  │  ← Mohit
│  (capture.py)   │
└────────┬────────┘
         │ packet_queue
         ▼
┌─────────────────┐
│feature_pipeline │  ← Ilma
│  (pipeline.py)  │
└────────┬────────┘
         │ ml_queue
         ▼
┌─────────────────┐
│   ai_engine     │  ← Kunal
│  (predict.py)   │
└────────┬────────┘
         │ verdict_queue
         ▼
┌─────────────────┐
│ firewall_engine │  ← Megha
│  (engine.py)    │
└────────┬────────┘
         │ audit log CSV
         ▼
┌─────────────────┐
│   dashboard     │  ← Priya
│   (app.py)      │
└─────────────────┘
```
