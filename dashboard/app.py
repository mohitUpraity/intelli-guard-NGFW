"""
Priya — Flask Dashboard + REST API
Run: python dashboard/app.py
Serves the admin UI and exposes API endpoints for all modules.
"""
from flask import Flask, jsonify, render_template
import pandas as pd, os

app = Flask(__name__, template_folder="templates", static_folder="static")

LOG_PATH = "data/logs/firewall_audit.csv"

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
        return jsonify({"total": 0, "blocked": 0, "allowed": 0, "alerts": 0})
    df = pd.read_csv(LOG_PATH)
    return jsonify({
        "total":   len(df),
        "blocked": int((df["verdict"] == "BLOCK").sum()),
        "allowed": int((df["verdict"] == "ALLOW").sum()),
        "alerts":  int((df["verdict"] == "ALERT").sum()),
    })

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
