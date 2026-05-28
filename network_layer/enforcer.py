"""
Mohit — Packet Enforcer
Integrates with Megha's firewall engine via dynamic iptables kernel-level rules.
"""
import subprocess
import logging
import platform

log = logging.getLogger("firewall_enforcer")

# Track dynamically blocked IPs to avoid redundant iptables rules
blocked_ips = set()

def is_linux():
    return platform.system().lower() == "linux"

def setup_iptables(queue_num: int = 1):
    """
    Sets up the firewall gateway environment.
    """
    if not is_linux():
        log.warning("[enforcer] Platform is not Linux. Operating in DEMO/EMULATION mode (No kernel hooks).")
        return
        
    try:
        # Check if root
        res = subprocess.run(["id", "-u"], capture_output=True, text=True)
        if res.stdout.strip() != "0":
            log.warning("[enforcer] Process is not running as root. iptables commands may fail.")
        log.info("[enforcer] Initializing Linux iptables enforcer...")
    except Exception as e:
        log.error(f"[enforcer] Failed to initialize: {e}")

def cleanup_iptables():
    """
    Flushes dynamic blocking rules injected by the firewall on shutdown.
    """
    if not is_linux():
        log.info("[enforcer] Flushed emulation state.")
        blocked_ips.clear()
        return

    log.info("[enforcer] Cleaning up dynamic firewall rules...")
    for ip in list(blocked_ips):
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    blocked_ips.clear()
    log.info("[enforcer] iptables cleanup complete.")

def enforce(verdict: str, features: dict):
    """
    Interferes/drops packets at the kernel level for malicious traffic.
    Called directly by Megha's firewall engine on verdict.
    """
    src_ip = features.get("src_ip", "")
    dst_ip = features.get("dst_ip", "")
    proto = features.get("proto", "ANY")
    dst_port = features.get("dst_port", 0)

    if not src_ip or src_ip == "127.0.0.1":
        # Never block localhost/empty IPs to prevent self-lockouts
        return

    if verdict == "BLOCK":
        if src_ip in blocked_ips:
            # Already blocked, skip redundant execution
            return
            
        log.warning(f"🚨 [ENFORCE-BLOCK] IP={src_ip} -> dst={dst_ip} [{proto}:{dst_port}]")
        blocked_ips.add(src_ip)

        if is_linux():
            try:
                # Inject a dynamic kernel drop rule for the malicious source IP
                cmd = ["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"]
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log.info(f"🛡️ [KERNEL-DROP] Injected drop rule for attacker: iptables -A INPUT -s {src_ip} -j DROP")
            except subprocess.CalledProcessError as e:
                log.error(f"❌ [KERNEL-ERROR] Failed to inject rule (check sudo/root permissions): {e}")
            except Exception as e:
                log.error(f"❌ [KERNEL-ERROR] An error occurred: {e}")
        else:
            log.info(f"✨ [EMULATION] macOS/Windows Emulated drop for IP: {src_ip}")

    elif verdict == "ALLOW":
        # Log flow pass
        log.info(f"✅ [ENFORCE-ALLOW] IP={src_ip} -> dst={dst_ip} [{proto}:{dst_port}]")

