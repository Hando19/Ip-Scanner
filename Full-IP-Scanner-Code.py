#!/usr/bin/env python3
"""
IP Scanner (Multi-Subnet, Labeled)
- Reads labeled subnets from a JSON config
- Scans each subnet, logs discovery timestamps per IP
- Prints active IPs, newly discovered IPs, and most recent IP per subnet
- Optionally opens newest IP in the browser

Example subnets.json:
{
   "Office": "192.168.1.0/24",
  "Warehouse": "192.168.2.0/24",
  "Lab": "10.0.0.0/24"
}
"""

import argparse
import concurrent.futures as cf
import ipaddress
import json
import os
import platform
import subprocess
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path

# -----------------------
# Paths & constants
# -----------------------
APPNAME = "IPScanner"
IS_WINDOWS = platform.system().lower().startswith("win")

def app_data_dir() -> Path:
    if IS_WINDOWS:
        base = os.getenv("APPDATA")
        if base:
            return Path(base) / APPNAME
        return Path.home() / APPNAME
    # macOS/Linux
    xdg = os.getenv("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / APPNAME
    return Path.home() / ".local" / "share" / APPNAME

LOG_DIR = app_data_dir()
LOG_DIR.mkdir(parents=True, exist_ok=True)

# -----------------------
# Ping implementation
# -----------------------
def ping(ip: str, timeout_ms: int = 1000) -> bool:
    """
    Returns True if a host responds to a single ping.
    Cross-platform flags:
      - Windows: ping -n 1 -w <ms>
      - Linux/macOS: ping -c 1 -W <sec>  (note: -W is seconds on Linux; macOS uses -W ms on some versions, but -W isn't portable on mac. We'll use -t / -W fallback.)
    """
    try:
        if IS_WINDOWS:
            # -n 1 one echo; -w timeout in ms
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            # Use -c 1 (1 packet) and a per-packet timeout in seconds
            # Prefer -W on Linux, fallback to -t on mac if needed.
            # We'll try -c 1 -W <sec> first; mac treats -W differently, but many builds accept it.
            seconds = max(1, int(round(timeout_ms / 1000)))
            cmd = ["ping", "-c", "1", "-W", str(seconds), ip]

        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.5, timeout_ms / 1000 + 0.5)
        )
        return result.returncode == 0
    except Exception:
        return False

# -----------------------
# Scanning
# -----------------------
def scan_network(subnet: str, workers: int = 256, timeout_ms: int = 1000):
    """
    Ping all hosts in the subnet concurrently and return list of active IPs (as strings).
    """
    net = ipaddress.ip_network(subnet, strict=False)
    # exclude network and broadcast if IPv4
    candidates = [str(ip) for ip in net.hosts()] if isinstance(net, ipaddress.IPv4Network) else [str(ip) for ip in net]
    active = []

    def task(ip):
        return ip if ping(ip, timeout_ms=timeout_ms) else None

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(task, candidates, chunksize=64):
            if res:
                active.append(res)

    # Keep sorted by numeric IP
    active.sort(key=lambda x: ipaddress.ip_address(x))
    return active

# -----------------------
# Logging & state
# -----------------------
def log_file_for_label(label: str) -> Path:
    # Sanitize label for filename
    safe = "".join(c for c in label if c.isalnum() or c in ("-", "_")).rstrip()
    return LOG_DIR / f"ip_discovery_log_{safe}.json"

def load_previous(log_path: Path) -> dict:
    if log_path.exists():
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_log(state: dict, log_path: Path) -> None:
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

def iso_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# -----------------------
# Per-subnet workflow
# -----------------------
def scan_subnet(label: str, subnet: str, open_behavior: str, timeout_ms: int, workers: int):
    """
    open_behavior: 'none' | 'new' | 'all'
      - none: never open
      - new: open only if there are newly discovered IPs (open the most recent)
      - all: always open the most recent IP for the subnet
    """
    print(f"\n🏢 Scanning {label} ({subnet})...")
    now = iso_now()
    log_path = log_file_for_label(label)

    # Validate subnet early
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        print(f"  ❌ Skipping: invalid subnet '{subnet}' ({e})")
        return

    previous_log = load_previous(log_path)
    current_ips = scan_network(subnet, workers=workers, timeout_ms=timeout_ms)

    # Show active IPs
    print("📋 Active IPs:")
    if current_ips:
        for ip in current_ips:
            print(f"  - {ip}")
    else:
        print("  (none)")

    # Determine newly seen IPs
    new_ips = []
    for ip in current_ips:
        if ip not in previous_log:
            previous_log[ip] = now
            new_ips.append(ip)

    if new_ips:
        print("\n📡 New IP(s) detected:")
        for ip in new_ips:
            print(f"  + {ip} (seen at {now})")
    else:
        print("\n✅ No new IPs detected.")

    # Most recent discovery in this subnet
    if previous_log:
        most_recent_ip, ts = max(previous_log.items(), key=lambda kv: kv[1])
        print(f"\n⏱️ Most recent IP: {most_recent_ip} (discovered at {ts})")

        should_open = (
            open_behavior == "all" or
            (open_behavior == "new" and len(new_ips) > 0)
        )
        if should_open:
            try:
                webbrowser.open(f"http://{most_recent_ip}")
            except Exception as e:
                print(f"  ⚠️ Could not open browser for {most_recent_ip}: {e}")

    save_log(previous_log, log_path)

# -----------------------
# Config
# -----------------------
def load_subnets_config(path: Path) -> dict:
    if not path.exists():
        print(f"❌ Config file not found: {path}")
        sys.exit(1)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Config JSON must be an object mapping 'Label' -> 'CIDR subnet'")
        # quick validation
        for label, subnet in data.items():
            if not isinstance(label, str) or not isinstance(subnet, str):
                raise ValueError("Each entry must be string label -> string subnet")
        return data
    except Exception as e:
        print(f"❌ Failed to read config: {e}")
        sys.exit(1)

# -----------------------
# CLI
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Multi-subnet IP discovery (labeled buildings)"
    )
    p.add_argument(
        "--config",
        default="subnets.json",
        help="Path to JSON config mapping labels to subnets (default: subnets.json)"
    )
    p.add_argument(
        "--open",
        choices=["none", "new", "all"],
        default="new",
        help="Open newest IP in browser: 'none' never, 'new' only when new IPs appear (default), 'all' always per subnet"
    )
    p.add_argument(
        "--timeout-ms",
        type=int,
        default=1000,
        help="Ping timeout per host in milliseconds (default: 1000)"
    )
    p.add_argument(
        "--workers",
        type=int,
        default=256,
        help="Max concurrent pings (default: 256)"
    )
    p.add_argument(
        "--every",
        type=int,
        default=0,
        help="Repeat scan every N seconds (0 = run once)"
    )
    return p.parse_args()

# -----------------------
# Main
# -----------------------
def main():
    args = parse_args()
    cfg_path = Path(args.config)
    subnets = load_subnets_config(cfg_path)

    if args.every > 0:
        print(f"⏲️ Running continuous scans every {args.every} seconds. Press Ctrl+C to stop.")
        try:
            while True:
                for label, subnet in subnets.items():
                    scan_subnet(label, subnet, args.open, args.timeout_ms, args.workers)
                print("\n" + "-"*60)
                time.sleep(max(1, args.every))
        except KeyboardInterrupt:
            print("\n👋 Stopped.")
    else:
        for label, subnet in subnets.items():
            scan_subnet(label, subnet, args.open, args.timeout_ms, args.workers)

if __name__ == "__main__":
    main()

