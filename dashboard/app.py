"""
Priya — Flask Dashboard + REST API
Run: python dashboard/app.py
Serves the admin UI and exposes API endpoints for all modules.
"""
from flask import Flask, jsonify, render_template, request
import pandas as pd, os, subprocess, sys, threading, time
from scapy.all import IP, TCP, UDP, ICMP, send, RandShort

app = Flask(__name__, template_folder="templates", static_folder="static")

LOG_PATH = "data/logs/firewall_audit.csv"

# --- SIMULATOR DAEMON STATE ---
class SimState:
    def __init__(self):
        self.active = False
        self.mode = "syn_flood"
        self.target = "127.0.0.1"
        self.intensity = 100  # packets per loop
        
sim_state = SimState()

@app.route("/api/sim_state", methods=["GET"])
def get_sim_state():
    return jsonify({
        "active": sim_state.active,
        "mode": sim_state.mode,
        "target": sim_state.target,
        "intensity": sim_state.intensity
    })
# ------------------------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/logs")
def get_logs():
    if not os.path.exists(LOG_PATH):
        return jsonify([])
    df = pd.read_csv(LOG_PATH).tail(200)
    return jsonify(df.to_dict(orient="records"))

@app.route("/api/stats")
def get_stats():
    if not os.path.exists(LOG_PATH):
        return jsonify({
            "total": 0, "blocked": 0, "allowed": 0, "alerts": 0, "latency_avg": 0.0,
            "protocols": {}, "sources": {}, "top_attackers": {}
        })
    df = pd.read_csv(LOG_PATH)
    latency_avg = float(df["latency_ms"].mean()) if "latency_ms" in df and len(df) > 0 else 0.0
    if pd.isna(latency_avg):
        latency_avg = 0.0
        
    protocols = df["proto"].value_counts().to_dict() if "proto" in df else {}
    sources = df["source"].value_counts().to_dict() if "source" in df else {}
    
    # Top 5 blocked IPs
    top_attackers = {}
    if "verdict" in df and "src_ip" in df:
        top_attackers = df[df["verdict"] == "BLOCK"]["src_ip"].value_counts().head(5).to_dict()

    return jsonify({
        "total":   len(df),
        "blocked": int((df["verdict"] == "BLOCK").sum()) if "verdict" in df else 0,
        "allowed": int((df["verdict"] == "ALLOW").sum()) if "verdict" in df else 0,
        "alerts":  int((df["verdict"] == "ALERT").sum()) if "verdict" in df else 0,
        "latency_avg": round(latency_avg, 2),
        "protocols": protocols,
        "sources": sources,
        "top_attackers": top_attackers
    })

@app.route("/api/simulate", methods=["POST"])
def simulate():
    data = request.json or {}
    command = data.get("command")
    
    if command == "start":
        sim_state.active = True
    elif command == "stop":
        sim_state.active = False
    elif command == "update":
        if "mode" in data: sim_state.mode = data["mode"]
        if "target" in data: sim_state.target = data["target"]
        if "intensity" in data: sim_state.intensity = int(data["intensity"])
    
    return jsonify({
        "status": "ok", 
        "active": sim_state.active,
        "mode": sim_state.mode,
        "target": sim_state.target,
        "intensity": sim_state.intensity
    })

@app.route("/api/threat_intel")
def get_threat_intel():
    if not os.path.exists(LOG_PATH):
        return jsonify({"clusters": [], "explanations": []})
    try:
        df = pd.read_csv(LOG_PATH).tail(500)
        blocked = df[df["verdict"] == "BLOCK"].copy()
        
        clusters_data = []
        explanations = []
        
        if len(blocked) > 0:
            grouped = blocked.groupby(["src_ip", "dst_port", "proto"]).size().reset_index(name="count")
            
            for _, row in grouped.iterrows():
                ip = row["src_ip"]
                port = int(row["dst_port"])
                count = int(row["count"])
                
                clusters_data.append({
                    "ip": ip,
                    "port": port,
                    "proto": row["proto"],
                    "count": count,
                    "type": "HTTP Flood" if port in [80, 443] else ("SSH Brute Force" if port == 22 else "Port Scan")
                })
            
            recent_blocks = blocked.drop_duplicates(subset=["src_ip"], keep="last").tail(10)
            
            for _, row in recent_blocks.iterrows():
                ip = row["src_ip"]
                port = int(row["dst_port"])
                score = float(row["score"])
                decision_src = row.get("source", "UNKNOWN")
                
                # Defensible logic: Generate explanations based on actual source
                if decision_src == "STATIC_RULE":
                    if port == 23: sig = "Static Rule Match: Telnet Blocked"
                    elif port == 4444: sig = "Static Rule Match: C2 Port Blocked"
                    else: sig = f"Static Rule Match: Port {port} Blocked"
                    confidence_str = "100%" # Rules are deterministic
                else: # AI_MODEL
                    if port in [80, 443]: sig = "AI Anomaly: Volumetric/SYN Flood Characteristics"
                    elif port == 22: sig = "AI Anomaly: SSH Brute Force Statistical Pattern"
                    else: sig = "AI Anomaly: Unrecognized High-Suspicion Traffic Profile"
                    confidence_str = f"{int(score*100)}%"
                
                explanations.append({
                    "ip": ip,
                    "port": port,
                    "score": round(score, 3),
                    "reason": sig,
                    "action": "Dropped connection at edge",
                    "confidence": confidence_str
                })
        
        return jsonify({
            "clusters": clusters_data,
            "explanations": explanations
        })
    except Exception as e:
        print(f"Error in threat intel: {e}")
        return jsonify({"clusters": [], "explanations": []})

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    import yaml
    try:
        with open("config.yaml") as f:
            config = yaml.safe_load(f)
        port = config["dashboard"]["port"]
    except Exception:
        port = 5001
        
    app.run(host="0.0.0.0", port=port, debug=False)
