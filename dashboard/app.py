# """
# Priya — Flask Dashboard + REST API
# Run: python dashboard/app.py
# Serves the admin UI and exposes API endpoints for all modules.
# """
# from flask import Flask, jsonify, render_template
# import pandas as pd, os

# app = Flask(__name__, template_folder="templates", static_folder="static")

# LOG_PATH = "data/logs/firewall_audit.csv"

# @app.route("/")
# def index():
#     return render_template("index.html")

# @app.route("/api/logs")
# def get_logs():
#     if not os.path.exists(LOG_PATH):
#         return jsonify([])
#     df = pd.read_csv(LOG_PATH).tail(200)
#     return jsonify(df.to_dict(orient="records"))

# @app.route("/api/stats")
# def get_stats():
#     if not os.path.exists(LOG_PATH):
#         return jsonify({"total": 0, "blocked": 0, "allowed": 0, "alerts": 0})
#     df = pd.read_csv(LOG_PATH)
#     return jsonify({
#         "total":   len(df),
#         "blocked": int((df["verdict"] == "BLOCK").sum()),
#         "allowed": int((df["verdict"] == "ALLOW").sum()),
#         "alerts":  int((df["verdict"] == "ALERT").sum()),
#     })

# @app.route("/api/health")
# def health():
#     return jsonify({"status": "ok"})

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000, debug=True)


from flask import Flask, render_template, jsonify
import random
import time

app = Flask(__name__)

# Dummy data (replace later with real logs)
logs = []

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/logs')
def get_logs():
    return jsonify(logs)

# Simulate logs (temporary)
def generate_logs():
    attacks = ["Normal", "SYN Flood", "Port Scan", "DDoS"]
    while True:
        log = {
            "ip": f"192.168.1.{random.randint(1,255)}",
            "status": random.choice(["ALLOWED", "BLOCKED"]),
            "attack": random.choice(attacks),
            "time": time.strftime("%H:%M:%S")
        }
        logs.append(log)
        if len(logs) > 20:
            logs.pop(0)
        time.sleep(2)

if __name__ == '__main__':
    import threading
    t = threading.Thread(target=generate_logs)
    t.start()
    app.run(debug=True)
