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

# Check if terminal supports color
def supports_color():
    plat = platform.system().lower()
    supported_platform = plat != 'windows' or 'ANSICON' in os.environ
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return supported_platform and is_a_tty

if supports_color():
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
else:
    GREEN = YELLOW = RED = BLUE = CYAN = WHITE = BOLD = RESET = ""

BANNER = f"""{CYAN}
========================================================================
 🛡️  INTELLIGUARD : NEXT-GENERATION RESILIENT SECURITY GATEWAY
========================================================================
 [System Status] Cross-Platform Deployment Gateway
 [Target Panel]  DRDO Internship Demonstration & Evaluation Mode
========================================================================{RESET}"""

def is_linux():
    return platform.system().lower() == "linux"

def check_and_install_dependencies():
    print(f"\n{BOLD}{BLUE}[+] Step 0: Checking System Dependencies...{RESET}")
    
    # Map requirements.txt names to python import names
    required_packages = {
        "pyyaml": "yaml",
        "colorama": "colorama",
        "tqdm": "tqdm",
        "flask": "flask",
        "flask-cors": "flask_cors",
        "scapy": "scapy",
        "pyshark": "pyshark",
        "pandas": "pandas",
        "numpy": "numpy",
        "scikit-learn": "sklearn",
        "joblib": "joblib",
        "xgboost": "xgboost",
        "tensorflow": "tensorflow",
        "onnx": "onnx",
        "matplotlib": "matplotlib",
        "seaborn": "seaborn"
    }
    
    # Netfilterqueue only on Linux
    if is_linux():
        required_packages["netfilterqueue"] = "netfilterqueue"
        
    missing = []
    for pip_name, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_name)
            
    if not missing:
        print(f" {GREEN}🟢 All core dependencies are installed.{RESET}")
        return True
        
    print(f" {YELLOW}⚠️  Detected {len(missing)} missing Python package(s):{RESET}")
    for pkg in missing:
        print(f"     - {pkg}")
        
    print(f"\n{BOLD}Select installation mode for DRDO Environment:{RESET}")
    print(f"  {BOLD}[1] Online Setup:{RESET} Automatically run 'pip3 install -r requirements.txt'")
    print(f"  {BOLD}[2] Offline Setup:{RESET} Install from a local USB/offline folder of Wheels (.whl)")
    print(f"  {BOLD}[3] Generate Offline Download Script:{RESET} Display commands to prepare offline dependencies")
    print(f"  {BOLD}[4] Manual Setup Instructions & Exit{RESET}")
    
    try:
        choice = input(f"\n{BOLD}👉 Enter choice (1-4, default: 1): {RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Exiting setup.")
        sys.exit(1)
        
    if not choice:
        choice = "1"
        
    if choice == "1":
        print(f"\n{BLUE}[*] Running: pip3 install -r requirements.txt ...{RESET}")
        try:
            cmd = [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
            if is_linux() and os.getuid() != 0:
                cmd.append("--user")
            subprocess.run(cmd, check=True)
            print(f" {GREEN}🟢 Dependencies installed successfully.{RESET}\n")
            return True
        except subprocess.CalledProcessError as e:
            print(f" {RED}❌ Installation failed. Please check internet connection or permissions.{RESET}")
            
    elif choice == "2":
        try:
            wheels_dir = input(f"\n{BOLD}Enter path to offline wheels folder (default: ./offline_wheels): {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Exiting setup.")
            sys.exit(1)
        if not wheels_dir:
            wheels_dir = "./offline_wheels"
            
        if not os.path.isdir(wheels_dir):
            print(f" {RED}❌ Error: Directory '{wheels_dir}' not found.{RESET}")
            print(f" Please place your downloaded Wheels (.whl) in '{wheels_dir}' first.")
        else:
            print(f"\n{BLUE}[*] Running offline installation: pip3 install --no-index --find-links={wheels_dir} -r requirements.txt ...{RESET}")
            try:
                cmd = [sys.executable, "-m", "pip", "install", "--no-index", f"--find-links={wheels_dir}", "-r", "requirements.txt"]
                subprocess.run(cmd, check=True)
                print(f" {GREEN}🟢 Offline dependencies installed successfully.{RESET}\n")
                return True
            except subprocess.CalledProcessError as e:
                print(f" {RED}❌ Offline installation failed. Ensure all wheel packages are present in the directory.{RESET}")
                
    elif choice == "3":
        print(f"\n{CYAN}========================================================================{RESET}")
        print(f"{BOLD}🛡️  OFFLINE PREPARATION GUIDE FOR DRDO LABS{RESET}")
        print(f"{CYAN}========================================================================{RESET}")
        print(" Run the following command on a machine with internet access:")
        print(f"   {GREEN}pip3 download -d offline_wheels -r requirements.txt{RESET}")
        print(f"\n {YELLOW}💡 IMPORTANT: If downloading from macOS/Windows but the DRDO target is Linux,{RESET}")
        print("    use this command instead to download Linux-compatible wheels:")
        print(f"      {GREEN}pip3 download --platform manylinux2014_x86_64 --only-binary=:all: --python-version 3.9 -d offline_wheels -r requirements.txt{RESET}")
        print("    (Adjust '--python-version' to match the target system's Python version)")
        print("\n Copy the entire project folder AND the newly created 'offline_wheels/'")
        print(" folder to a USB drive/CD and transfer them to the offline target system.")
        print("\n Once transferred, run 'python3 run_demo.py' and select option [2] to install.")
        print(f"{CYAN}========================================================================{RESET}\n")
        sys.exit(0)
        
    # Manual / Exit option
    print(f"\n{CYAN}========================================================================{RESET}")
    print(f"{BOLD}🛠️  MANUAL SYSTEM SETUP GUIDE{RESET}")
    print(f"{CYAN}========================================================================{RESET}")
    print(f"{BOLD}1. Setup Python 3 & Pip:{RESET}")
    print("   - Ubuntu/Debian: sudo apt update && sudo apt install -y python3 python3-pip")
    print("   - CentOS/RHEL:   sudo dnf install -y python3 python3-pip")
    print("   - macOS:         brew install python")
    print("   - Windows:       Install from python.org (check 'Add python.exe to PATH')")
    print(f"\n{BOLD}2. Install Packages:{RESET}")
    print(f"   {GREEN}pip3 install -r requirements.txt{RESET}")
    if is_linux():
        print(f"\n{BOLD}3. Linux Netfilter Dependencies (Required for Kernel Mode):{RESET}")
        print("   sudo apt install -y build-essential python3-dev libnetfilter-queue-dev")
    print(f"\n{BOLD}4. Start the Application:{RESET}")
    print("   - Non-root (macOS/Win/Linux Mock):  python3 run_demo.py")
    print("   - Kernel mode (Linux Live):         sudo python3 run_demo.py")
    print(f"{CYAN}========================================================================{RESET}\n")
    sys.exit(0)

def check_and_train_model():
    model_path = "ai_engine/models/firewall_model.pkl"
    if os.path.exists(model_path):
        return
        
    print(f"\n{YELLOW}⚠️  AI Model file '{model_path}' is missing.{RESET}")
    print("   (Note: Model files are git-ignored to prevent pushing massive binaries).")
    print("   We can automatically generate a synthetic dataset and train the model in ~3 seconds.")
    
    try:
        ans = input(f"\n{BOLD}👉 Auto-train the AI Firewall model now? (y/n, default: y): {RESET}").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Exiting setup.")
        sys.exit(1)
        
    if not ans or ans.startswith('y'):
        print(f"\n{BLUE}[+] Step 0.1: Generating high-fidelity training dataset...{RESET}")
        try:
            # Add parent dir to path so imports work
            sys.path.insert(0, BASE_DIR)
            from ai_engine.generate_dataset import generate_dataset
            generate_dataset("ai_engine/data/custom_dataset.csv")
            
            print(f"\n{BLUE}[+] Step 0.2: Training Random Forest Classifier...{RESET}")
            from ai_engine.train_rf import train
            train()
            print(f" {GREEN}🟢 AI Model and Scaler trained and saved successfully!{RESET}\n")
        except Exception as e:
            print(f" {RED}❌ Auto-training failed: {e}{RESET}")
            print(" You can try running them manually:")
            print("   python3 ai_engine/generate_dataset.py")
            print("   python3 ai_engine/train_rf.py")
            sys.exit(1)
    else:
        print(f" {RED}❌ AI Model is required to run the firewall. Exiting.{RESET}")
        sys.exit(1)

def check_log_file():
    log_path = "data/logs/firewall_audit.csv"
    log_dir = os.path.dirname(log_path)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    if not os.path.exists(log_path):
        with open(log_path, "w") as f:
            f.write("timestamp,src_ip,dst_ip,proto,dst_port,score,verdict,source,latency_ms\n")
        print(f" {GREEN}🟢 Created clean audit log file at {log_path}{RESET}")

def main():
    print(BANNER)
    
    # Run setup, dependency checks, model training, and log initialization
    if not check_and_install_dependencies():
        sys.exit(1)
        
    check_and_train_model()
    check_log_file()
    
    # OS Checks and DRDO Tips
    if is_linux():
        print(f" {GREEN}🔍 OS Status: Linux Gateway detected.{RESET}")
        res = subprocess.run(["id", "-u"], capture_output=True, text=True)
        if res.stdout.strip() != "0":
            print(f" {YELLOW}⚠️  WARNING: Running on Linux but not as root/sudo.{RESET}")
            print("     Live packet capture (Scapy) and kernel iptables rules require root.")
            print("     Recommendation: Restart using 'sudo python3 run_demo.py'")
            time.sleep(2)
        else:
            print(f" {GREEN}🟢 Success: Operating in full Kernel-Level Interception Mode (iptables active).{RESET}")
    else:
        print(f" {GREEN}🔍 OS Status: macOS/Windows development system detected.{RESET}")
        print(f" {GREEN}🟢 Success: Operating in High-Fidelity Tactical Emulation Mode.{RESET}")
        print("     Sniffing & kernel enforcers will run in mock demonstration mode.")
        time.sleep(1)
        
    print(f"\n{BLUE}[+] Step 1: Booting Flask Cyber Command Dashboard...{RESET}")
    
    dashboard_proc = None
    try:
        # Start Flask dashboard in background
        dashboard_proc = subprocess.Popen(
            [sys.executable, "dashboard/app.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1.5)  # Wait for Flask to boot
        print(f" {GREEN}✅ Dashboard online at http://localhost:5001{RESET}")
        
        # 2. Open browser automatically
        print(f"{BLUE}[+] Step 2: Accessing command interface...{RESET}")
        webbrowser.open("http://localhost:5001")
        
        # 3. Boot Firewall Gateway
        print(f"{BLUE}[+] Step 3: Launching Hybrid AI/Signature Gateway Core...{RESET}")
        print(f" {BOLD}🛡️  Press Ctrl+C to terminate the session and flush rules.{RESET}\n")
        time.sleep(1)
        
        # Execute main.py inside the main thread
        import main
        
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[*] Caught shutdown signal. Flushing all temporary rules...{RESET}")
    finally:
        # 4. Graceful Cleanup
        if dashboard_proc:
            print(f"{BLUE}[+] Terminating Dashboard UI process...{RESET}")
            dashboard_proc.terminate()
            dashboard_proc.wait()
            
        try:
            # Import enforcer directly to run cleanup
            from network_layer import enforcer
            enforcer.cleanup_iptables()
        except Exception as e:
            print(f" {YELLOW}[!] Warning: Could not cleanly flush rules: {e}{RESET}")
            
        print(f"{GREEN}🛡️  IntelliGuard NGFW shut down cleanly. Session concluded.{RESET}")

if __name__ == "__main__":
    main()
