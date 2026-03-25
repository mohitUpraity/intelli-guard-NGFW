"""
IntelliGuard Firewall — Entry Point
Starts all modules as concurrent threads.
Run: sudo python main.py
"""
import threading, queue, yaml

with open("config.yaml") as f:
    config = yaml.safe_load(f)

from network_layer.capture       import start_capture
from feature_pipeline.pipeline   import run as run_pipeline
from ai_engine.predict           import run as run_ai, verdict_queue
from firewall_engine.engine      import run as run_engine

# Patch verdict_queue into firewall engine
import firewall_engine.engine as fe
fe.verdict_queue = verdict_queue

threads = [
    threading.Thread(target=start_capture,  args=(config["network"]["interface"],), daemon=True),
    threading.Thread(target=run_pipeline,   daemon=True),
    threading.Thread(target=run_ai,         args=(verdict_queue,), daemon=True),
    threading.Thread(target=run_engine,     daemon=True),
]

for t in threads:
    t.start()

print("\n🛡  IntelliGuard is running. Ctrl+C to stop.\n")

try:
    for t in threads:
        t.join()
except KeyboardInterrupt:
    print("\n[*] Shutting down.")
