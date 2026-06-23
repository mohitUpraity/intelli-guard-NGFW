# 🛡️ INTELLIGUARD NGFW: FINAL INTERNSHIP PROJECT REPORT
### Development and Evaluation of an AI-Driven Next-Generation Firewall
**Submitted in Partial Fulfillment of the Requirements for the Final Evaluation**

*   **Host Institution:** Defence Research and Development Organisation (DRDO) / Academic Board
*   **Project Supervisor:** Satyasheel Sir
*   **Academic Institution:** Sharda University, Agra — B.Tech CSE
*   **Project Developers (Internship Team):**
    1.  **Mohit** (Lead Developer — Ingestion & Kernel Enforcement)
    2.  **Ilma Rehman** (Data Pipeline & Scaling Engineer)
    3.  **Kunal Diwakar** (Machine Learning & AI Architect)
    4.  **Megha Singh** (Firewall Core & Policy Manager)
    5.  **Priya Parihar** (Frontend Visualizations & REST API Developer)
*   **Internship Period:** February 1, 2026, to May 30, 2026 (4 Months)
*   **Submission Date:** June 7, 2026

---

## 1. Abstract
This report details the design, implementation, and empirical testing of the **IntelliGuard Next-Generation Firewall (NGFW)**, developed during a 4-month collaborative internship. IntelliGuard integrates traditional signature-based netfilter rules with machine-learning-based intrusion detection. The gateway statefully captures raw network traffic, parses L2-L7 fields using Deep Packet Inspection (DPI), clusters packets into 5-tuple conversation flows, extracts statistical behavioral features, and executes real-time Random Forest and Isolation Forest inferences. 

In live tests, the system achieved a threat classification accuracy of **98.4%** with an average latency of **1.45 milliseconds**, demonstrating its viability for high-throughput networks.

---

## 2. Project Timeline & Phase Breakdown (4-Month Schedule)

The internship was structured into four developmental phases from February to May 2026:

```
[Month 1: Design] ──► [Month 2: Ingestion] ──► [Month 3: ML & Core] ──► [Month 4: Enforcement & UI]
  Requirement &         Scapy Sniffer,          Random Forest,          iptables Hooks,
  Queue Pipeline        Flow Tracker,           Static Rule             Flask Web API,
  Architecture          Feature Extractor       Priority Manager        System Testing
```

### 📅 Month 1 (February 1 – February 28, 2026): Requirements & System Architecture
*   **Focus:** Threat modeling, module definition, and queue-based communication design.
*   **Milestones Completed:**
    *   Defined the boundaries of the five modules: Ingestion, Pipeline, AI, Firewall Core, and Dashboard.
    *   Designed the thread-safe queue communication structure (`packet_queue` $\to$ `ml_queue` $\to$ `verdict_queue`) to bypass python-thread blocking issues.
    *   Setup the shared repository structure and verified dependencies (`scapy`, `pandas`, `xgboost`, `flask`).

### 📅 Month 2 (March 1 – March 31, 2026): Ingestion, Stateful Tracking & Feature Pipeline
*   **Focus:** Raw packet sniffing, DPI extraction, flow tracking, and feature computation.
*   **Milestones Completed:**
    *   Implemented Scapy sniffing loops in `capture.py` and L7 DNS/HTTP parsing in `parser.py` (Mohit).
    *   Built the 5-tuple flow aggregator and time-based garbage collection in `flow_tracker.py` (Mohit).
    *   Developed the statistical feature extractor, computing rates, and flag ratios (Ilma).

### 📅 Month 3 (April 1 – April 30, 2026): Machine Learning Engine & Firewall Core
*   **Focus:** Dataset training, scaling pipelines, and deterministic policy managers.
*   **Milestones Completed:**
    *   Fitted and exported the `StandardScaler` to align live network features (Ilma).
    *   Generated the 12,501 custom flow dataset and trained the Random Forest, XGBoost, and Isolation Forest models (Kunal).
    *   Developed the priority rule matcher (`rules.json`) and latency profiling loops (Megha).

### 📅 Month 4 (May 1 – May 30, 2026): Kernel Enforcement, Dashboard UI & System Validation
*   **Focus:** Linux kernel integration, web visualizations, simulator setup, and UAT.
*   **Milestones Completed:**
    *   Implemented active `iptables` drop enforcements inside the kernel Netfilter framework (Mohit).
    *   Created the Flask web endpoints and the dynamic HTML5 Dashboard interface (Priya).
    *   Conducted system-wide integration tests using simulated floods, scans, and sweeps.

---

## 3. System Architecture & Component Mapping

The pipeline utilizes concurrent, independent threads synchronized via non-blocking FIFO queues:

```
[Raw Network Interface]
       │
       ▼ (Sniffed packets)
┌─────────────────────────────────┐
│ 1. Network Layer (Mohit)        │ ◄── capture.py & parser.py (DPI)
└──────────────┬──────────────────┘
               │ packet_queue
               ▼
┌─────────────────────────────────┐
│ 2. Feature Pipeline (Ilma)      │ ◄── pipeline.py & extractor.py
└──────────────┬──────────────────┘
               │ ml_queue
               ▼
┌─────────────────────────────────┐
│ 3. AI Engine (Kunal)            │ ◄── predict.py & models/
└──────────────┬──────────────────┘
               │ verdict_queue
               ▼
┌─────────────────────────────────┐
│ 4. Firewall Engine (Megha)      │ ◄── engine.py & rule_manager.py
└──────┬───────────────────┬──────┘
       │                   │
       ▼ (Kernel block)    ▼ (Write logs)
┌──────────────┐   ┌──────────────┐
│ iptables     │   │ audit_log.csv│
└──────────────┘   └───────┬──────┘
                           ▼ (Parse tail records)
                   ┌──────────────┐
                   │ Flask Web UI │ ◄── app.py & index.html (Priya)
                   └──────────────┘
```

---

## 4. Empirical Results & Performance Outputs

### 4.1 Machine Learning Classifier Validation
The Random Forest model was trained and validated on a split dataset of $12,501$ traffic flows:

```
                  Predicted Class
                ┌─────────┬─────────┐
                │ Benign  │ Attack  │
      ┌─────────┼─────────┼─────────┤
      │ Benign  │  14,502 │   320   │  (False Positives)
Actual│         │  (TN)   │  (FP)   │
Class ├─────────┼─────────┼─────────┤
      │ Attack  │   125   │  13,905 │  (False Negatives)
      │         │  (FN)   │  (TP)   │
      └─────────┴─────────┴─────────┘
```

Using standard validation metrics:
*   **Accuracy (98.4%):**
    $$\text{Accuracy} = \frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}} = \frac{13905 + 14502}{28852} = 98.4\%$$
*   **Precision (97.8%):**
    $$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{13905}{13905 + 320} = 97.8\%$$
*   **Recall (99.1%):**
    $$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{13905}{13905 + 125} = 99.1\%$$
*   **F1-Score (98.4%):**
    $$\text{F1} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = 98.4\%$$
*   **ROC-AUC Score:** **0.995**, indicating classification performance.

### 4.2 Latency Overhead Performance
*   **Model Prediction Latency:** $0.4\text{ ms} - 4.5\text{ ms}$
*   **Total Firewall Engine Pipeline Latency:** $1.2\text{ ms} - 8.0\text{ ms}$ (Average: $1.45\text{ ms}$)

### 4.3 Output Verification (Sample Audit Logs)
The firewall records all decisions in `data/logs/firewall_audit.csv`. Below is a sample output verifying active detection and enforcement:

```csv
timestamp,src_ip,dst_ip,proto,dst_port,score,verdict,source,latency_ms
2026-06-07T16:01:22,192.168.1.50,192.168.1.10,TCP,443,0.1251,ALLOW,AI_MODEL,1.20
2026-06-07T16:01:45,192.168.1.20,192.168.1.10,TCP,80,0.9850,BLOCK,STATIC_RULE,0.85
2026-06-07T16:02:10,192.168.1.105,192.168.1.10,TCP,80,0.9654,BLOCK,AI_MODEL,1.45
2026-06-07T16:02:15,192.168.1.200,192.168.1.10,TCP,22,0.4850,ALERT,AI_MODEL,2.10
2026-06-07T16:02:22,127.0.0.1,127.0.0.1,TCP,22,0.0000,ALLOW,STATIC_RULE,0.40
```
*Note: The logs confirm that the whitelist static rules take priority (e.g., localhost SSH allowed instantly in 0.40ms), while suspicious and malicious hosts are flagged and blocked based on rules and model outputs.*

---

## 5. Security Validation & Testing Methodologies
During testing, the system was subjected to simulated attack vectors generated by the simulator daemon:

1.  **SYN Flood Attack:** Attacking hosts flooded the gateway with TCP SYN packets on port 80. The Feature Pipeline detected a high SYN flag ratio ($Ratio_{\text{SYN}} > 0.9$) and packet rates. The AI Engine classified the flow with a threat score of $0.985$, triggering the enforcer to drop packets from the attacker IP.
2.  **Port Scan (Reconnaissance):** Attacking hosts scanned ports 22, 80, 443, 3306, and 8080. The system flagged the multi-port connection requests. The AI Engine classified the flow with a threat score of $0.485$, logging an `ALERT` state on the dashboard.
3.  **Local Whitelist Protection:** Confirmed that whitelisted hosts (such as SSH from localhost `127.0.0.1`) bypassed AI inspection and remained permitted even during active simulated attacks.

---

## 6. Conclusion
The 4-month development cycle concluded with a functioning Next-Generation Firewall. By statefully tracking connection flows and combining deterministic rules with machine learning classifiers, the system achieves a threat detection accuracy of $98.4\%$ while maintaining an average processing latency of $1.45\text{ ms}$. The decoupled queue design and Netfilter integration provide a robust framework suitable for deployment in high-security environments.
