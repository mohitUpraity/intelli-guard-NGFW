# 🔥 AI Engine – Next Generation Firewall
**Owner: Kunal Diwakar**
## 📌 Overview

This module implements an AI-based intrusion detection system for a Next Generation Firewall.
It analyzes network traffic and classifies it into security actions like BLOCK, ALERT, or ALLOW.

---

## ⚙️ Features

* Machine Learning-based threat detection
* Real-time decision logic
* High accuracy (~99%)
* Lightweight and fast inference
* Modular and scalable design

---

## 🧠 Model Details

* Algorithm: Random Forest Classifier
* Dataset: KDD Cup 99
* Task: Network intrusion detection
* Output: Firewall decision (ALLOW / ALERT / BLOCK)

---

## 🚦 Decision Logic

| Score     | Action |
| --------- | ------ |
| > 0.9     | BLOCK  |
| 0.7 – 0.9 | ALERT  |
| < 0.7     | ALLOW  |

---

## 📁 Project Structure

```
ai_engine/
│
├── predict.py          # Prediction logic
├── evaluate.py         # Model evaluation
├── train_xgboost.py    # (Planned - not implemented)
├── train_iforest.py    # (Planned - not implemented)
├── models/
│     └── firewall_model.pkl   # Trained model
```

---

## ▶️ Usage

### Load Model

```python
import joblib
model = joblib.load("models/firewall_model.pkl")
```

### Predict

```python
from predict import predict_threat

result = predict_threat(sample_input)
print(result)
```

---

## 📊 Evaluation

* Classification Report used
* Confusion Matrix generated
* Accuracy: ~99%

---

## 🚀 Future Scope

* Add XGBoost model
* Add Isolation Forest (anomaly detection)
* Real-time traffic integration
* Dashboard visualization

---

## 👨‍💻 Contribution

AI Engine module developed with model training, prediction logic, and deployment-ready structure.

