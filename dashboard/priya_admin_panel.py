"""
priya_admin_panel.py
---------------------
Priya — Dashboard Module Upgrade (Admin Panel)

This file is intentionally kept SEPARATE from app.py so that none of the
existing dashboard code has to be touched. It is wired in with exactly
TWO lines added to app.py (see the README at the bottom of this file).

Implements the "Priya Parihar (Dashboard)" remaining-work items from the
review feedback PDF:
  1. Interface selection UI            -> /api/admin/interfaces (+select)
  2. Target device selection UI        -> /api/admin/device
  3. Real Traffic / Simulation mode    -> /api/admin/mode
  4. Device monitoring dashboard       -> /api/admin/device/traffic
  5. Firewall rule management UI       -> /api/admin/firewall/rules
  6. Device discovery display          -> /api/admin/network/scan
  + a rendered Admin Panel page        -> GET /admin

All state is persisted to small JSON files under data/ so it survives
restarts, and none of it interferes with the existing firewall_audit.csv
pipeline or the existing index.html dashboard.
"""

import os
import json
import socket
import platform
import subprocess
import uuid
import ipaddress
from datetime import datetime

import pandas as pd
import psutil
from flask import Blueprint, jsonify, request, render_template

priya_bp = Blueprint("priya_admin", __name__)

# --- Paths (kept consistent with app.py's LOG_PATH, defined independently
#     here so this file has zero import dependency on app.py) -------------
LOG_PATH = "data/logs/firewall_audit.csv"
DEVICE_CONFIG_PATH = "data/admin/device_config.json"
RULES_PATH = "data/admin/firewall_rules.json"


# =========================================================================
# 1. PERSISTED STATE
# =========================================================================
class DeviceState:
    """Holds the admin's current interface / target device / mode choices."""

    def __init__(self):
        self.interface = None
        self.target_ip = None
        self.target_label = ""
        self.mode = "simulation"  # "real" or "simulation"
        self._load()

    def _load(self):
        if os.path.exists(DEVICE_CONFIG_PATH):
            try:
                with open(DEVICE_CONFIG_PATH, "r") as f:
                    data = json.load(f)
                self.interface = data.get("interface")
                self.target_ip = data.get("target_ip")
                self.target_label = data.get("target_label", "")
                self.mode = data.get("mode", "simulation")
            except Exception as e:
                print(f"[priya_admin_panel] could not load device config: {e}")

    def save(self):
        os.makedirs(os.path.dirname(DEVICE_CONFIG_PATH), exist_ok=True)
        with open(DEVICE_CONFIG_PATH, "w") as f:
            json.dump(
                {
                    "interface": self.interface,
                    "target_ip": self.target_ip,
                    "target_label": self.target_label,
                    "mode": self.mode,
                },
                f,
                indent=2,
            )

    def as_dict(self):
        return {
            "interface": self.interface,
            "target_ip": self.target_ip,
            "target_label": self.target_label,
            "mode": self.mode,
        }


device_state = DeviceState()


def load_rules():
    if not os.path.exists(RULES_PATH):
        return []
    try:
        with open(RULES_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_rules(rules):
    os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)
    with open(RULES_PATH, "w") as f:
        json.dump(rules, f, indent=2)


# =========================================================================
# 2. NETWORK INTERFACE SELECTION
# =========================================================================
def classify_interface(name):
    n = name.lower()
    if "wi-fi" in n or "wlan" in n or "wireless" in n:
        return "Wi-Fi"
    if n.startswith("eth") or "ethernet" in n:
        return "Ethernet"
    if "tun" in n or "tap" in n or "vpn" in n or "ppp" in n:
        return "VPN"
    if n in ("lo", "loopback") or "loopback" in n:
        return "Loopback"
    return "Other"


def get_mac(addr_list):
    for a in addr_list:
        family_name = str(a.family)
        if hasattr(psutil, "AF_LINK") and a.family == psutil.AF_LINK:
            return a.address
        if "AF_LINK" in family_name or "AF_PACKET" in family_name:
            return a.address
    return None


@priya_bp.route("/api/admin/interfaces", methods=["GET"])
def list_interfaces():
    """List every network interface available on this host."""
    interfaces = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            ipv4 = next((a.address for a in addr_list if a.family == socket.AF_INET), None)
            mac = get_mac(addr_list)
            is_up = stats[name].isup if name in stats else False
            interfaces.append(
                {
                    "name": name,
                    "type": classify_interface(name),
                    "ip": ipv4,
                    "mac": mac,
                    "status": "up" if is_up else "down",
                }
            )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "interfaces": []}), 500

    return jsonify({"status": "ok", "interfaces": interfaces, "selected": device_state.interface})


@priya_bp.route("/api/admin/interfaces/select", methods=["POST"])
def select_interface():
    data = request.json or {}
    iface = data.get("interface")
    if not iface:
        return jsonify({"status": "error", "message": "interface is required"}), 400
    device_state.interface = iface
    device_state.save()
    return jsonify({"status": "ok", "interface": iface})


# =========================================================================
# 3. NETWORK DISCOVERY ("Scan Network")
# =========================================================================
def guess_local_subnet():
    """Best-effort guess of the LAN subnet in CIDR form, e.g. 192.168.1.0/24."""
    try:
        addrs = psutil.net_if_addrs()
        for name, addr_list in addrs.items():
            for a in addr_list:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    if a.netmask:
                        iface = ipaddress.IPv4Interface(f"{a.address}/{a.netmask}")
                        return str(iface.network)
    except Exception:
        pass
    return "192.168.1.0/24"


@priya_bp.route("/api/admin/network/scan", methods=["POST"])
def scan_network():
    """
    ARP-sweeps the local subnet to discover devices, e.g.:
      192.168.1.1   Router
      192.168.1.10  Laptop
      192.168.1.50  Mobile
    Requires admin/root privileges for raw ARP packets, exactly like the
    rest of the network layer (it reuses scapy, already a project dependency).
    """
    data = request.json or {}
    subnet = data.get("subnet") or guess_local_subnet()

    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        return jsonify(
            {"status": "error", "message": "scapy is not installed", "devices": []}
        ), 500

    devices = []
    try:
        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(broadcast / arp_request, timeout=2, verbose=0)

        for _, received in answered:
            ip = received.psrc
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = None
            devices.append(
                {
                    "ip": ip,
                    "mac": received.hwsrc,
                    "hostname": hostname or "Unknown Device",
                }
            )
        devices.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    except PermissionError:
        return jsonify(
            {
                "status": "error",
                "message": "Network scan requires administrator/root privileges.",
                "devices": [],
            }
        ), 403
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "devices": []}), 500

    return jsonify({"status": "ok", "subnet": subnet, "count": len(devices), "devices": devices})


# =========================================================================
# 4. TARGET DEVICE SELECTION  /  IP FILTERING
# =========================================================================
@priya_bp.route("/api/admin/device", methods=["GET", "POST"])
def target_device():
    if request.method == "POST":
        data = request.json or {}
        ip = data.get("ip")
        if not ip:
            return jsonify({"status": "error", "message": "ip is required"}), 400
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"status": "error", "message": "invalid ip address"}), 400

        device_state.target_ip = ip
        device_state.target_label = data.get("label", "")
        device_state.save()
        return jsonify({"status": "ok", "target_ip": ip, "label": device_state.target_label})

    return jsonify({"target_ip": device_state.target_ip, "label": device_state.target_label})


# =========================================================================
# 5. REAL TRAFFIC vs SIMULATION MODE
# =========================================================================
@priya_bp.route("/api/admin/mode", methods=["GET", "POST"])
def traffic_mode():
    if request.method == "POST":
        data = request.json or {}
        mode = data.get("mode")
        if mode not in ("real", "simulation"):
            return jsonify({"status": "error", "message": "mode must be 'real' or 'simulation'"}), 400
        device_state.mode = mode
        device_state.save()
        return jsonify({"status": "ok", "mode": mode})

    return jsonify({"mode": device_state.mode})


# =========================================================================
# 6. DEVICE MONITORING DASHBOARD (stats scoped to the selected target IP)
# =========================================================================
@priya_bp.route("/api/admin/device/traffic", methods=["GET"])
def device_traffic():
    target = device_state.target_ip
    empty = {
        "target_ip": target,
        "total": 0,
        "blocked": 0,
        "allowed": 0,
        "alerts": 0,
        "recent": [],
    }
    if not target or not os.path.exists(LOG_PATH):
        return jsonify(empty)

    try:
        df = pd.read_csv(LOG_PATH)
    except Exception:
        return jsonify(empty)

    if "src_ip" not in df.columns and "dst_ip" not in df.columns:
        return jsonify(empty)

    mask = pd.Series(False, index=df.index)
    if "src_ip" in df.columns:
        mask = mask | (df["src_ip"] == target)
    if "dst_ip" in df.columns:
        mask = mask | (df["dst_ip"] == target)
    filtered = df[mask]

    return jsonify(
        {
            "target_ip": target,
            "total": len(filtered),
            "blocked": int((filtered["verdict"] == "BLOCK").sum()) if "verdict" in filtered else 0,
            "allowed": int((filtered["verdict"] == "ALLOW").sum()) if "verdict" in filtered else 0,
            "alerts": int((filtered["verdict"] == "ALERT").sum()) if "verdict" in filtered else 0,
            "recent": filtered.tail(50).to_dict(orient="records"),
        }
    )


# =========================================================================
# 7. FIREWALL RULE MANAGEMENT (dynamic, admin-driven)
# =========================================================================
def apply_system_block(ip):
    """
    Best-effort OS-level enforcement so a rule isn't just cosmetic.
    Safe to call even without privileges: failures are caught and reported
    back to the admin panel rather than crashing the request.
    """
    system = platform.system()
    try:
        if system == "Linux":
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, timeout=5, capture_output=True,
            )
        elif system == "Windows":
            rule_name = f"IntelliGuard_Block_{ip}"
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"],
                check=True, timeout=5, capture_output=True,
            )
        else:
            return False, f"Unsupported OS for enforcement: {system}"
        return True, None
    except FileNotFoundError:
        return False, "Firewall control binary not found on this host"
    except subprocess.CalledProcessError as e:
        return False, f"Command failed: {e}"
    except Exception as e:
        return False, str(e)


def remove_system_block(ip):
    system = platform.system()
    try:
        if system == "Linux":
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, timeout=5, capture_output=True,
            )
        elif system == "Windows":
            rule_name = f"IntelliGuard_Block_{ip}"
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                check=True, timeout=5, capture_output=True,
            )
        return True, None
    except Exception as e:
        return False, str(e)


@priya_bp.route("/api/admin/firewall/rules", methods=["GET"])
def get_rules():
    return jsonify({"rules": load_rules()})


@priya_bp.route("/api/admin/firewall/rules", methods=["POST"])
def add_rule():
    data = request.json or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "ip is required"}), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"status": "error", "message": "invalid ip"}), 400

    rules = load_rules()
    rule = {
        "id": uuid.uuid4().hex[:8],
        "ip": ip,
        "action": data.get("action", "BLOCK"),
        "reason": data.get("reason", "Manually added by admin"),
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "enforced": False,
        "enforce_error": None,
    }

    if data.get("enforce", False):
        ok, err = apply_system_block(ip)
        rule["enforced"] = ok
        rule["enforce_error"] = err

    rules.append(rule)
    save_rules(rules)
    return jsonify({"status": "ok", "rule": rule})


@priya_bp.route("/api/admin/firewall/rules/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    rules = load_rules()
    target = next((r for r in rules if r["id"] == rule_id), None)
    if not target:
        return jsonify({"status": "error", "message": "rule not found"}), 404

    if target.get("enforced"):
        remove_system_block(target["ip"])

    rules = [r for r in rules if r["id"] != rule_id]
    save_rules(rules)
    return jsonify({"status": "ok"})


# =========================================================================
# 8. ADMIN SUMMARY + PAGE
# =========================================================================
@priya_bp.route("/api/admin/summary", methods=["GET"])
def admin_summary():
    return jsonify(
        {
            **device_state.as_dict(),
            "rule_count": len(load_rules()),
        }
    )


@priya_bp.route("/admin")
def admin_panel():
    return render_template("admin.html")
