# 🧠 Feature Pipeline Module (Ilma Rehman)

## 📌 Overview

The **Feature Pipeline Module** is a core component of the IntelliGuard Firewall system. It acts as a transformation layer between raw network traffic and the AI/ML detection engine.

This module receives structured packet data from the network layer, converts it into meaningful features, preprocesses the data, and forwards it to the machine learning model for threat detection.

---

## 🔄 Data Flow

```
network_layer → feature_pipeline → ai_engine
     (Mohit)         (Ilma)         (Kunal)
```

---

## ⚙️ Responsibilities

* Convert raw packet data into **flow-based features**
* Perform **feature engineering** for anomaly detection
* Apply **data preprocessing and scaling**
* Ensure **real-time processing with low latency**
* Provide **ML-ready input** to the AI engine

---

## 🧩 Module Structure

```
feature_pipeline/
│
├── extractor.py         # Feature engineering logic
├── preprocessor.py      # Data cleaning & scaling
├── pipeline.py          # Real-time processing pipeline
├── dataset_builder.py   # Dataset preparation for training
└── __init__.py
```

---

## 🔍 Feature Engineering

### 📊 Flow-Based Features

* Packet count (`pkt_count`)
* Byte count (`byte_count`)
* Flow duration (`duration`)

### 📈 Statistical Features

* Mean packet size (`mean_pkt_size`)
* Standard deviation (`std_pkt_size`)

### 🌐 Protocol Features

* TCP, UDP, ICMP encoding

### 🚨 Behavioral Features

* SYN flag count (`syn_flag`)
* FIN flag count (`fin_flag`)
* RST flag count (`rst_flag`)

### ⚡ Advanced Features

* Packet rate (`packet_rate`)
* Byte rate (`byte_rate`)
* SYN ratio (`syn_ratio`)

---

## 🧹 Preprocessing

The preprocessing pipeline ensures data consistency and ML compatibility:

* Feature alignment using fixed column order
* Missing value handling
* Data scaling using **StandardScaler**
* Conversion to ML-ready numerical format

---

## 🔁 Real-Time Pipeline

The pipeline continuously processes incoming network data:

1. Receive packet from `network_layer`
2. Group packets into flows
3. Extract features from flows
4. Apply preprocessing
5. Send processed data to `ml_queue`

---

## 🧪 Setup & Usage

### 1️⃣ Install Dependencies

```
pip install numpy pandas scikit-learn joblib
```

---

### 2️⃣ Fit Scaler (Required Once)

```python
from feature_pipeline.preprocessor import fit_and_save
import pandas as pd

df = pd.DataFrame([sample_features])
fit_and_save(df)
```

---

### 3️⃣ Run Pipeline

```python
from feature_pipeline.pipeline import run

run()
```

---

## 📤 Output

The module outputs:

* Scaled feature vectors (NumPy arrays)
* Sent to `ml_queue` for AI-based threat detection

---

## 🧠 Key Design Highlights

* Real-time processing using queues
* Flow-based analysis (not just packet-level)
* ML-friendly feature engineering
* Modular and scalable design
* Seamless integration with AI engine

---

## 🤝 Integration

This module integrates with:

* **Network Layer (Mohit)** → Input data source
* **AI Engine (Kunal)** → Consumes processed features

---

## 📌 Status

✅ Feature extraction implemented
✅ Advanced feature engineering completed
✅ Preprocessing pipeline integrated
✅ Real-time pipeline functional

---

## 👩‍💻 Author

**Ilma Rehman**
Feature Engineering & Data Pipeline Engineer

---
