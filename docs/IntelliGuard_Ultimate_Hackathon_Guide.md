# 🛡️ IntelliGuard NGFW: The Ultimate Hackathon & Project Defense Guide
### The Complete Technical, Code, and Dashboard Reference Manual for Winning Presentations

**Project Supervisor:** Satyasheel Sir  
**Institution:** Sharda University, Agra — B.Tech CSE Final Project  
**Target Panel:** DRDO Technical Evaluation Committee / Hackathon Jury  
**Deployment State:** High-Fidelity Tactical Emulation & Linux Kernel Netfilter Active  

---

## 🏆 The Hackathon Pitch (Elevator Pitch)
> "Traditional firewalls are static, rule-bound, and blind. They block yesterday's threats but let tomorrow's zero-days slip by. **IntelliGuard NGFW** is a software-defined, next-generation firewall that combines traditional signature rules with live machine learning. By grouping raw packets statefully into conversation flows, extracting statistical protocol rates, and executing real-time ensemble model inference, IntelliGuard calculates a dynamic threat probability score. It dynamically drops malicious IP addresses at the Linux kernel level (`iptables`) in under **1.5 milliseconds**, while visualizing active network telemetry on a stunning tactical command dashboard. It is secure, decoupled, ultra-fast, and zero-setup."

---

## 🎙️ Presenter's Speaking Hook (30-Second Opener)
*(Speak this clearly when introducing the project to catch the panel's attention)*
> "Good morning, Sirs. Today we are demonstrating **IntelliGuard NGFW**, a Next-Generation Firewall. Traditional firewalls are static and blind to pattern-based or zero-day attacks. IntelliGuard solves this by utilizing **stateful connection flows and machine learning**. 
> Our system captures raw packets, aggregates them into conversational streams, extracts behavioral statistics, and runs real-time ML inference to dynamically block malicious IPs at the Linux kernel level in under **1.5 milliseconds**. Let me walk you through the module architecture and our live tactical command console."

---

## 1. Project Vision & Architecture (What & Why)

### 1.1 The Firewall Evolution
*   **Legacy Firewalls (L3/L4):** Filter packets based on static rules (e.g., *Block IP X, Allow Port Y*). They fail against IP rotation, spoofing, and multi-packet volumetric floods.
*   **IntelliGuard NGFW (L7 + AI):** Performs **Deep Packet Inspection (DPI)** to parse application headers (DNS names, HTTP methods) and aggregates packet streams into **Stateful Flows**. It uses behavioral machine learning to detect attacks based on traffic pattern anomalies rather than static signatures.

### 1.2 The Decoupled Concurrency Pipeline
To prevent network interface bottlenecks, the system is engineered using a **multi-threaded consumer-producer model**. Thread-safe FIFO queues (`queue.Queue`) decouple the CPU-heavy AI inference from the I/O-heavy packet sniffing.

```
[Raw Network Traffic]
        │
        ▼ (Captured via Scapy sniffing)
┌────────────────────────────────────────────────────────┐
│ 1. Network Layer (capture.py) — Thread 1 (Mohit)        │
│    - Sniffs packets, parses L7 headers, clusters flows │
└───────────────────────┬────────────────────────────────┘
                        │ packet_queue.put()
                        ▼
┌────────────────────────────────────────────────────────┐
│ 2. Feature Pipeline (pipeline.py) — Thread 2 (Ilma)   │
│    - Buffers flows, extracts features, scales vectors  │
└───────────────────────┬────────────────────────────────┘
                        │ ml_queue.put()
                        ▼
┌────────────────────────────────────────────────────────┐
│ 3. AI Engine (predict.py) — Thread 3 (Kunal)          │
│    - Evaluates Random/XGBoost models, weights scores   │
└───────────────────────┬────────────────────────────────┘
                        │ verdict_queue.put()
                        ▼
┌────────────────────────────────────────────────────────┐
│ 4. Firewall Engine (engine.py) — Thread 4 (Megha)     │
│    - Rules priority check, latency logger, kernel drop │
└───────────┬────────────────────────────────────────────┘
            │
            ├─────────────────────────────────┐
            ▼ (Execute dropped packet)        ▼ (Append rows)
┌───────────────────────────┐     ┌──────────────────────────┐
│ iptables / Kernel hook    │     │ data/logs/audit.csv      │
└───────────────────────────┘     └───────────┬──────────────┘
                                              ▼ (Poll logs via Pandas)
                                  ┌──────────────────────────┐
                                  │ 5. Dashboard (app.py)   │ (Priya)
                                  │    - Flask REST Server   │
                                  │    - Web UI visualization│
                                  └──────────────────────────┘
```

---

## 2. Team Roles & Decoupled Code Flow (How)

| Teammate | Module Folder | Role | Code Files | Key Logic |
|---|---|---|---|---|
| **Mohit** | `network_layer/` | Core Ingestion & Enforcement | `capture.py`, `parser.py`, `flow_tracker.py`, `enforcer.py` | Scapy sniffing, DNS/HTTP parsing, 5-tuple flow grouping, `iptables` drop rules. |
| **Ilma Rehman** | `feature_pipeline/` | Pipeline & Scaling | `pipeline.py`, `extractor.py`, `preprocessor.py` | Minimum flow thresholding ($\ge 5$ packets), 16 feature extraction, `StandardScaler` normalization. |
| **Kunal Diwakar** | `ai_engine/` | AI/ML Models | `predict.py`, `train_rf.py`, `train_iforest.py` | Multi-class probability threat formula, Random Forest / Isolation Forest inference. |
| **Megha Singh** | `firewall_engine/` | Firewall Engine | `engine.py`, `rule_manager.py`, `audit_log.py` | Static rule matching priority, AI fallback trigger, CSV logging, latency profiling. |
| **Priya Parihar** | `dashboard/` | Command Dashboard | `app.py`, `templates/index.html` | Flask REST endpoints, live log parsing, simulator controls. |

---

### 2.1 Network Layer Code Flow & Speaking Script (Mohit)
*   **Raw Capture (`capture.py`):** Sniffs traffic via Scapy. Falls back to simulated polling on Windows/macOS environments.
*   **Deep Parser (`parser.py`):** DPI engine extracting L2 MACs, L7 DNS domain names, and L7 HTTP methods (`GET`/`POST`).
*   **Stateful Flow Tracker (`flow_tracker.py`):** Groups packets using a 5-tuple key: `(src_ip, dst_ip, src_port, dst_port, proto)`. Deletes idle flows older than $60\text{ seconds}$ to prevent memory saturation.
*   **Active Enforcer (`enforcer.py`):** Updates Netfilter stack via subprocess: `iptables -A INPUT -s <attacker_ip> -j DROP`.
*   **Presenter Speaking Script (What to say):**
    > *"Sir, my module is the Network Layer. It acts as the gateway's sensory organ and muscle. It captures raw packets using Scapy, performs Deep Packet Inspection to extract Layer 7 DNS and HTTP attributes, and groups packets statefully into 5-tuple connection flows. Finally, when the AI flags a threat, my module writes dynamic drop rules directly to the Linux `iptables` kernel stack to sever the connection instantly."*

### 2.2 Feature Pipeline Code Flow & Speaking Script (Ilma Rehman)
*   **Flow Threshold (`pipeline.py`):** Fetches packet records and delays feature calculation until a flow clusters $\ge 5$ packets.
*   **Extractor (`extractor.py`):** Extracts 16 statistical metrics including rate calculations:
    $$\text{packet\_rate} = \frac{\text{pkt\_count}}{\text{duration}}, \quad \text{byte\_rate} = \frac{\text{byte\_count}}{\text{duration}}, \quad \text{syn\_ratio} = \frac{\text{syn\_flag}}{\text{pkt\_count}}$$
*   **Standard Scaler (`preprocessor.py`):** Aligns features and normalizes values using `StandardScaler` fit variables ($z = \frac{x - \mu}{\sigma}$).
*   **Presenter Speaking Script (What to say):**
    > *"Sir, my module is the Feature Pipeline. It acts as the translation layer between raw headers and machine learning. To optimize speed, we only extract statistics once a flow clusters 5 or more packets. We compute 16 features including packet rates and TCP flags, standardizing them using standard scaling so they are parsed uniformly by the AI."*

### 2.3 AI Engine Code Flow & Speaking Script (Kunal Diwakar)
*   **Model Inference (`predict.py`):** Evaluates scaled features via Random Forest (`firewall_model.pkl`) to output probability class distributions: Benign, Alert, and Block.
*   **Threat Score Formula:**
    $$S = \big(P(\text{Alert}) \times 0.45\big) + \big(P(\text{Block}) \times 0.95\big)$$
*   **Threshold Execution:** $S > 0.55 \implies$ **BLOCK** | $S > 0.40 \implies$ **ALERT** | otherwise **ALLOW**.
*   **Isolation Forest Anomaly Classifier (`train_iforest.py`):** Unsupervised model running in parallel to identify zero-day outliers.
*   **Presenter Speaking Script (What to say):**
    > *"Sir, my module is the AI Engine. We run a multi-class Random Forest model to calculate a threat score. If the score crosses 0.55, the firewall blocks the IP; if it is between 0.40 and 0.55, it alerts the administrator; otherwise, it allows it. We also run an unsupervised Isolation Forest model in parallel to flag anomalous zero-day traffic."*

### 2.4 Firewall Engine Code Flow & Speaking Script (Megha Singh)
*   **Decision Priority (`engine.py`):** Intercepts threat verdicts and checks static rules (`rules.json`) first. If unmatched (`PASS`), it executes the AI engine's probabilistic verdict.
*   **Audit Logger (`audit_log.py`):** Measures system latency ($T_{\text{verdict}} - T_{\text{capture}}$) and writes results to `firewall_audit.csv`.
*   **Presenter Speaking Script (What to say):**
    > *"Sir, my module is the Firewall Engine. It acts as the central policy authority. It evaluates static rules first to ensure critical connections are whitelisted. If no static rules match, it queries the AI model's score. It then records the decision, along with the processing latency in milliseconds, to our audit logs."*

### 2.5 Command Dashboard Code Flow & Speaking Script (Priya Parihar)
*   **Web Console (`app.py`):** Hosts the Flask web server.
*   **Log Aggregator:** Utilizes Pandas to chunk the audit CSV tail, extracting averages, distributions, and top adversaries.
*   **Presenter Speaking Script (What to say):**
    > *"Sir, my module is the Command Dashboard. It hosts our Flask REST APIs. It reads the system audit logs, aggregates real-time metrics, and serves them to our web control panel so administrators can monitor the firewall and control the simulator."*

---

## 3. The Cyber Command Dashboard: Widget-by-Widget Mapping
*(Use this breakdown to explain each visual element during the live presentation)*

### 3.1 Header Navigation & Action Elements
*   **Navigation Tabs:**
    *   *Overview:* The main monitoring interface containing live throughput, KPIs, and attacker lists.
    *   *Threat Intel:* Deep analytical visualizations including neural scatter plots and attack vector radars.
    *   *Performance Report:* Model evaluation metrics (F1-score, precision, confusion matrix).
    *   *System Logs:* Real-time scrollable log audit.
*   **"Start Fresh" Button (`clear-btn`):**
    *   *What:* Triggers a POST request to `/api/clear` to wipe the audit CSV.
    *   *Why:* Wipes historical data to start a clean testing session.
    *   *How to explain:* *"If I click 'Start Fresh', the firewall flushes all historical logs and drops the charts back to zero, allowing us to evaluate a new live test session."*
*   **"Hacker Simulator" Button (`sim-btn`):** Toggles the Hacker Console configuration overlay to control traffic generators.
*   **System Status Indicator:** A pulsing green dot showing "SYSTEM SECURE" during baseline monitoring, changing to a flashing red "SIM ACTIVE" state when simulator mode is enabled.

### 3.2 Overview Tab Widgets
*   **Five KPI Cards:**
    *   *Total Flows:* Total connection streams inspected.
    *   *Permitted:* Count of benign allowed flows (`ALLOW`).
    *   *Intercepted:* Count of malicious dropped flows (`BLOCK`).
    *   *Threat Alerts:* Count of suspicious flagged flows (`ALERT`).
    *   *Processing Latency:* Average evaluation latency ($T_{\text{verdict}} - T_{\text{capture}}$).
    *   *How to explain:* *"These five cards show our system health in real-time. The most critical metric is Processing Latency, which averages around 1.45 milliseconds, proving the AI does not degrade connection speeds."*
*   **Live Traffic Throughput Chart:** A rolling line graph showing incoming packet rates over time.
*   **Engine Activity Chart:** A doughnut chart comparing AI-driven interceptions against static rule blocks.
*   **Protocol Distribution Chart:** A pie chart displaying traffic breakdown by protocol (TCP, UDP, ICMP).
*   **Neural Anomaly Index:** An area chart showing the rolling average threat score (0.0 to 1.0) of processed flows.
    *   *How to explain:* *"This Neural Anomaly Index shows overall network risk. A spike here indicates an active scan or flood is underway."*
*   **Engine Processing Latency Chart:** Plots live latency in milliseconds to monitor system overhead.
*   **Top Blocked Adversaries Panel:** Lists the most active blocked IPs, limited dynamically by a UI slider.

### 3.3 Threat Intel Tab Widgets
*   **Neural Decision Space Scatter Plot:** Displays captured traffic mapped by Destination Port (Y-axis) and AI Threat Score (X-axis).
    *   *How to explain:* *"This scatter plot maps destination ports against threat scores. Legitimate HTTPS traffic clusters in the bottom-right (low score, port 443), while SYN floods cluster in the top-left (high score, port 80)."*
*   **Attack Vector Radar Chart:** Plots intercepted attack counts across key destination ports (HTTP 80, HTTPS 443, SSH 22, Other).
*   **Live Threat Telemetry Panel:** Lists recent blocked IPs with the confidence rating, engine source tag (`AI MODEL` or `STATIC RULE`), and justification (e.g. *SSH Brute Force Statistical Pattern*).

### 3.4 Performance Report Tab Widgets
*   **Model Accuracy Metrics:** Shows Accuracy, Precision, Recall, and F1-Scores.
*   **Real-time Confidence Trend:** A line graph displaying model confidence levels.
*   **Confusion Matrix Table:** Displays True Positive, True Negative, False Positive, and Negative counts.
*   **Global Metrics:** Displays the average model confidence and the ROC-AUC score ($0.995$).

### 3.5 System Logs Tab Widgets
*   **Real-Time Flow Audit Table:** Displays a rolling log of processed network traffic with timestamp, source/destination IPs, protocol, port, latency, threat score, engine type, and final verdict.

---

## 4. The Hacker Console Sliders (Detailed Mapping)
*(Use this to explain how adjusting sliders alters the simulation traffic properties)*

*   **1. Simulator Switch:** Toggle to activate or deactivate the background packet generation daemon.
*   **2. Real-World Mix Slider:** Generates a balanced mix of traffic (75% Benign, 15% Alert, 10% Bad).
*   **3. SYN Flood Slider:** Injects high-volume TCP connection requests (TCP port 80, SYN flag active) to test defense against connection exhaustion.
*   **4. UDP Flood Slider:** Injects bandwidth saturation traffic (UDP random ports) to test rate-limiting thresholds.
*   **5. ICMP Sweep Slider:** Generates ICMP echo requests (pings) targeting host ranges to test scanning detection.
*   **6. Port Scan Slider:** Generates TCP SYN packets targeting common ports (22, 80, 443, 3306, 8080) to test reconnaissance scanning detection.
*   **7. HTTP Flood Slider:** Generates TCP packets targeting port 80 with PSH-ACK flags active to simulate application-layer overload.
*   **8. Ping of Death Slider:** Generates ICMP packets carrying 60,000-byte payloads to test protocol exploit defenses.
*   **9. Xmas Scan Slider:** Generates TCP packets with FIN, PSH, and URG flags active to test stealth scanning detection.
*   **10. Attacker IPs Slider:** Sets the number of virtual attacker host IPs to simulate distributed attacks (DDoS).
*   **11. Target IP Input:** Sets the destination IP address for the simulated attacks.

---

## 5. Mathematical Foundations & Metrics

### 5.1 Flow Calculations
*   **Flow Duration ($D$):**
    $$D = T_{\text{max}} - T_{\text{min}}$$
*   **Packet Rate ($R_p$):**
    $$R_p = \frac{N}{D} \quad (\text{if } D > 0, \text{ else } N)$$
*   **Byte Rate ($R_b$):**
    $$R_b = \frac{\sum_{i=1}^N \text{size}_i}{D} \quad (\text{if } D > 0, \text{ else } \sum \text{size}_i)$$
*   **SYN Flag Ratio ($Ratio_{\text{SYN}}$):**
    $$Ratio_{\text{SYN}} = \frac{C_{\text{SYN}}}{N}$$

### 5.2 Machine Learning Validation Formulas
*   **Accuracy (98.4%):**
    $$\text{Accuracy} = \frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}}$$
*   **Precision (97.8%):**
    $$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$
*   **Recall / Sensitivity (99.1%):**
    $$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
*   **F1-Score (98.4%):**
    $$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

---

## 6. Hackathon Defense Q&A Preparation Sheet

#### Q1: What is the benefit of grouping packets into flows rather than analyzing packet-by-packet?
> **Answer:** "Packet-by-packet analysis is blind to volumetric and reconnaissance attacks. A single SYN packet is normal. However, 500 SYN packets sent from a single IP to one port in under 5 milliseconds indicates a SYN flood attack. Grouping packets into flows based on connection attributes allows the system to compute behavioral statistics like packet rates, byte rates, and flag ratios, enabling accurate classification of complex threat patterns."

#### Q2: How does the system handle high-throughput traffic without creating a bottleneck?
> **Answer:** "We implemented a decoupled, multi-threaded queue pipeline. The Network Layer sniffs packets and writes them directly to `packet_queue`. The Feature Pipeline pulls, aggregates, and standardizes them, pushing features to `ml_queue`. The AI Engine evaluates inference and pushes verdicts to `verdict_queue`. This decoupled design allows packet capturing to continue at high speed even under model inference or log output delays, preventing packet loss at the network card buffer."

#### Q3: Why is the Threat Score weighted as $P(\text{Alert}) \times 0.45 + P(\text{Block}) \times 0.95$ instead of using argmax?
> **Answer:** "Argmax is a hard classification mapping that ignores class probabilities. If a flow is classified with $P(\text{Benign}) = 0.34$, $P(\text{Alert}) = 0.33$, and $P(\text{Block}) = 0.33$, argmax would label it benign. Our weighted threat score calculates:
> $$S = (0.33 \times 0.45) + (0.33 \times 0.95) = 0.148 + 0.313 = 0.461$$
> Since $0.461$ crosses the alert threshold ($0.40$), the firewall flags the suspicious activity rather than ignoring it, ensuring critical edge cases are identified."

#### Q4: What happens if your machine learning model encounters a new/unknown attack?
> **Answer:** "We have designed a hybrid model strategy. While the supervised Random Forest/XGBoost classifier excels at detecting known signature categories (SYN Floods, sweeps, scans), we train an unsupervised **Isolation Forest (iForest)** model in parallel. Isolation Forest isolates anomalies by randomly partitioning features. Since abnormal traffic patterns require fewer splits to isolate in a decision tree, they register high anomaly scores, enabling the firewall to flag and block entirely unseen attack structures."

#### Q5: How do you prevent locking out authorized users if your model makes a mistake?
> **Answer:** "We enforce a strict **deterministic rule priority**. Before traffic is analyzed by the AI model, the Firewall Engine checks the static `rules.json` file. Legitimate critical connections, such as SSH from the local loopback interface (`127.0.0.1`), are explicitly white-listed as `ALLOW`. Only when no static rules apply does the engine delegate to the AI model's verdict."

#### Q6: How does the system handle encrypted TLS (HTTPS) traffic? Doesn't encryption break your Layer 7 Deep Packet Inspection (DPI)?
> **Answer:** "Encryption hides the HTTP payload (like GET request parameters), but it does not hide Layer 3/4 headers or the initial plaintext handshake. During the TLS handshake, the Client Hello message exposes the **Server Name Indication (SNI)** in plaintext, which lists the domain name being visited. Our parser extracts the SNI domain from the TLS handshake, and the flow tracker calculates behavioral metrics (like encrypted byte rates and packet intervals) to classify the flow, allowing us to detect anomalies in HTTPS streams without decrypting the payload."

---

## 🚀 7. Step-by-Step Hackathon Demo Script

Follow these steps during your live presentation to showcase the firewall's capabilities:

1.  **Boot the System:**
    Run `python3 run_demo.py`. This opens the Cyber Command Console in the browser at `http://localhost:5001`.
2.  **Establish the Baseline:**
    Show the dashboard displaying $0$ traffic and a "SYSTEM SECURE" status.
    *   **Speak:** *"Sir, here is our tactical cyber command console. The status indicator shows 'SYSTEM SECURE', and our traffic charts are at baseline. The dashboard displays zero active alerts or blocks."*
3.  **Activate the Simulator:**
    Open the Hacker Console, toggle the power switch, and set the **Real-World Mix** to $400\text{ pkt/s}$. Close the overlay.
    *   **Speak:** *"I will now simulate normal network activity. As you can see, traffic throughput spikes. Our feature pipeline and AI model process the traffic statefully, allowing it through with a latency of around 1.4 milliseconds. The protocol distribution chart updates to show TCP/UDP ratios."*
4.  **Launch a Volumetric Attack:**
    Open the Hacker Console, drag the **SYN Flood** slider to $800\text{ pkt/s}$, and close it.
    *   **Speak:** *"Now, I will simulate an attacker launching a volumetric SYN flood. Notice the immediate reaction on the dashboard. The throughput spikes, and the Neural Anomaly Index rises. The AI engine detects the anomaly, classifies the flow as malicious, and commands the enforcer to block the source IP."*
5.  **Demonstrate Threat Intel & Rule priority:**
    Click the **Threat Intel** tab.
    *   **Speak:** *"Under the Threat Intel tab, we can see the attack coordinates clustered on the Neural Decision Space scatter plot. The Live Threat Telemetry panel displays the blocked attacker's IP, the target port, and explains that the block was triggered due to volumetric SYN flood characteristics. Meanwhile, white-listed administrative hosts remain completely unaffected, proving rule-matching priority."*
6.  **Conclude:**
    Stop the simulation, show the traffic dropping to $0$, click **"Start Fresh"** to clear the logs, and conclude the demonstration.
    *   **Speak:** *"I will now stop the simulation. The traffic drops back to baseline. By clicking 'Start Fresh', the firewall flushes all active logs and resets the dashboard telemetry, ready for the next session."*
