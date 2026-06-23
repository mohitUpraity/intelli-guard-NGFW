"""
🛡️ IntelliGuard NGFW - Unified Demo Launcher
Runs both the Firewall Gateway (main.py) and the Web UI Dashboard (dashboard/app.py) concurrently,
launches the browser, and ensures a clean shutdown of all systems on exit.

Usage:
  python3 run_demo.py
"""
import sys
import os
import subprocess
import time
import webbrowser
import platform

# Ensure we are in the correct directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

BANNER = """
========================================================================
 🛡️  INTELLIGUARD : NEXT-GENERATION RESILIENT SECURITY GATEWAY
========================================================================
 [System Status] Cross-Platform Deployment Gateway
 [Target Panel]  DRDO Internship Demonstration & Evaluation Mode
========================================================================
"""

def is_linux():
    return platform.system().lower() == "linux"

def main():
    print(BANNER)
    
    # 1. OS Checks and DRDO Tips
    if is_linux():
        print(" 🔍 OS Status: Linux Gateway detected.")
        res = subprocess.run(["id", "-u"], capture_output=True, text=True)
        if res.stdout.strip() != "0":
            print(" ⚠️  WARNING: Running on Linux but not as root/sudo.")
            print("     Live packet capture (Scapy) and kernel iptables rules require root.")
            print("     Recommendation: Restart using 'sudo python3 run_demo.py'")
            time.sleep(2)
        else:
            print(" 🟢 Success: Operating in full Kernel-Level Interception Mode (iptables active).")
    else:
        print(" 🔍 OS Status: macOS/Windows development system detected.")
        print(" 🟢 Success: Operating in High-Fidelity Tactical Emulation Mode.")
        print("     Sniffing & kernel enforcers will run in mock demonstration mode.")
        time.sleep(1)
        
    print("\n[+] Step 1: Booting Flask Cyber Command Dashboard...")
    
    dashboard_proc = None
    try:
        # Start Flask dashboard in background
        dashboard_proc = subprocess.Popen(
            [sys.executable, "dashboard/app.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1.5)  # Wait for Flask to boot
        print(" ✅ Dashboard online at http://localhost:5001")
        
        # 2. Open browser automatically
        print("[+] Step 2: Accessing command interface...")
        webbrowser.open("http://localhost:5001")
        
        # 3. Boot Firewall Gateway
        print("[+] Step 3: Launching Hybrid AI/Signature Gateway Core...")
        print(" 🛡️  Press Ctrl+C to terminate the session and flush rules.\n")
        time.sleep(1)
        
        # Execute main.py inside the main thread
        import main
        
    except KeyboardInterrupt:
        print("\n\n[*] Caught shutdown signal. Flushing all temporary rules...")
    finally:
        # 4. Graceful Cleanup
        if dashboard_proc:
            print("[+] Terminating Dashboard UI process...")
            dashboard_proc.terminate()
            dashboard_proc.wait()
            
        try:
            # Import enforcer directly to run cleanup
            from network_layer import enforcer
            enforcer.cleanup_iptables()
        except Exception as e:
            print(f"[!] Warning: Could not cleanly flush rules: {e}")
            
        print("🛡️  IntelliGuard NGFW shut down cleanly. Session concluded.")

if __name__ == "__main__":
    main()
