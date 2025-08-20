#!/usr/bin/env python3
# Simple IP Scanner GUI (PySimpleGUI v5)
# - Pre-set labeled subnets (edit PRESET_SUBNETS below)
# - Users pick which buildings to scan
# - Shows Active IPs, New IPs, Most Recent; ALWAYS opens newest IP in browser
# - Saves per-subnet discovery logs in %APPDATA%\IPScanner\

import os, platform, subprocess, json, ipaddress, webbrowser, time, threading
from datetime import datetime
from pathlib import Path
import concurrent.futures as cf

try:
    import PySimpleGUI as sg  # v5
except Exception:
    print(
        "PySimpleGUI v5 is required.\n"
        "Install with:\n"
        "  python -m pip install --extra-index-url https://PySimpleGUI.net/install PySimpleGUI\n"
    )
    raise

# --------- ADMIN: Set your building subnets here ----------
PRESET_SUBNETS = {
  "Office": "192.168.1.0/24",
  "Warehouse": "192.168.2.0/24",
  "Lab": "10.0.0.0/24"
    # Add more as needed...
}
# ----------------------------------------------------------

APPNAME = "IPScanner"
IS_WINDOWS = platform.system().lower().startswith("win")

# ---------- Data paths ----------
def app_data_dir() -> Path:
    if IS_WINDOWS:
        base = os.getenv("APPDATA") or str(Path.home())
        return Path(base) / APPNAME
    xdg = os.getenv("XDG_DATA_HOME")
    return Path(xdg) / APPNAME if xdg else Path.home() / ".local" / "share" / APPNAME

DATA_DIR = app_data_dir()
DATA_DIR.mkdir(parents=True, exist_ok=True)

def log_path_for(label: str) -> Path:
    safe = "".join(c for c in label if c.isalnum() or c in ("-","_")).rstrip()
    return DATA_DIR / f"ip_discovery_log_{safe}.json"

# ---------- State load/save ----------
def load_state(label: str) -> dict:
    p = log_path_for(label)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_state(label: str, state: dict):
    p = log_path_for(label)
    p.write_text(json.dumps(state, indent=2), encoding="utf-8")

def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ---------- Ping + scan ----------
def ping(ip: str, timeout_ms: int = 1000) -> bool:
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            secs = max(1, int(round(timeout_ms/1000)))
            cmd = ["ping", "-c", "1", "-W", str(secs), ip]
        r = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.5, timeout_ms/1000 + 0.5),
        )
        return r.returncode == 0
    except Exception:
        return False

def scan_subnet_hosts(cidr: str, workers: int, timeout_ms: int):
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in net.hosts()]
    active = []

    def task(ip):
        return ip if ping(ip, timeout_ms) else None

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(task, hosts, chunksize=64):
            if res:
                active.append(res)

    active.sort(key=lambda x: ipaddress.ip_address(x))
    return active

# ---------- One-subnet workflow (runs in thread) ----------
def scan_one(label: str,
             cidr: str,
             timeout_ms: int,
             workers: int,
             ui_key: str,
             window: "sg.Window"):
    t0 = time.time()

    # Validate CIDR early
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        window.write_event_value(ui_key, f"❌ {label}: invalid subnet '{cidr}' ({e})\n")
        return

    window.write_event_value(ui_key, f"\n🏢 Scanning {label} ({cidr})...\n")
    state = load_state(label)
    active = scan_subnet_hosts(cidr, workers, timeout_ms)

    if active:
        window.write_event_value(
            ui_key,
            "📋 Active IPs:\n" + "\n".join(f"  - {ip}" for ip in active) + "\n",
        )
    else:
        window.write_event_value(ui_key, "📋 Active IPs:\n  (none)\n")

    now = now_str()
    new_ips = []
    for ip in active:
        if ip not in state:
            state[ip] = now
            new_ips.append(ip)

    if new_ips:
        window.write_event_value(
            ui_key,
            "\n📡 New IP(s) detected:\n" + "\n".join(f"  + {ip} (seen at {now})") + "\n",
        )
    else:
        window.write_event_value(ui_key, "\n✅ No new IPs detected.\n")

    if state:
        most_recent_ip, ts = max(state.items(), key=lambda kv: kv[1])
        window.write_event_value(
            ui_key, f"\n⏱️ Most recent IP: {most_recent_ip} (discovered at {ts})\n"
        )
        # CHANGED: Always open newest IP in browser (no dropdown/conditions)
        try:
            webbrowser.open(f"http://{most_recent_ip}")
        except Exception as e:
            window.write_event_value(ui_key, f"  ⚠️ Could not open browser: {e}\n")

    save_state(label, state)
    window.write_event_value(ui_key, f"⏲️ Done {label} in {time.time()-t0:.1f}s\n")

# ---------- Thread driver ----------
def scan_worker(subnets_dict: dict,
                labels_to_scan,
                timeout_ms: int,
                workers: int,
                ui_key: str,
                window: "sg.Window"):
    labels = labels_to_scan or list(subnets_dict.keys())
    for lbl in labels:
        scan_one(lbl, subnets_dict[lbl], timeout_ms, workers, ui_key, window)
    window.write_event_value(ui_key, "\n" + "-"*60 + "\n")

# ---------- GUI ----------
def build_window():
    sg.theme("SystemDefault")
    labels = list(PRESET_SUBNETS.keys())

    layout = [
        [sg.Text("IP Scanner", font=("Segoe UI", 16)), sg.Push(),
         sg.Text(f"Logs: {DATA_DIR}", text_color="gray")],
        [sg.Text("Select buildings to scan:")],
        [sg.Listbox(labels, key="-LIST-", select_mode=sg.SELECT_MODE_EXTENDED, size=(32, 8))],
        [sg.Text("Timeout (ms)"), sg.Input("1000", key="-TO-", size=(8,1)),
         sg.Text("Workers"), sg.Input("256", key="-WK-", size=(6,1)),
         sg.Text("  (Newest IP will open in your browser automatically)", text_color="gray")],
        [sg.Button("Scan Selected", size=(14,1)), sg.Button("Scan All", size=(10,1)),
         sg.Button("Clear Output"), sg.Button("Exit")],
        [sg.Text("Output:")],
        [sg.Multiline("", key="-OUT-", size=(92, 24), autoscroll=True, font=("Consolas", 10), expand_x=True, expand_y=True)]
    ]
    return sg.Window("IP Scanner", layout, resizable=True, finalize=True)

def main():
    window = build_window()
    worker_thread = None

    def log(msg: str):
        window["-OUT-"].print(msg, end="")

    while True:
        event, values = window.read(timeout=200)
        if event == sg.WINDOW_CLOSED or event == "Exit":
            break

        # pump logs from worker thread
        if isinstance(event, str) and event == "-OUT-":
            msg = values.get(event, "")
            if msg:
                log(msg)
        elif isinstance(event, tuple) and len(event) == 2 and event[0] is None and event[1][0] == "-OUT-":
            log(event[1][1])

        if event == "Clear Output":
            window["-OUT-"].update("")

        if event in ("Scan Selected", "Scan All"):
            if worker_thread and worker_thread.is_alive():
                sg.popup("A scan is already running. Please wait.")
                continue

            # read controls
            try:
                timeout_ms = int(values["-TO-"])
                workers = int(values["-WK-"])
            except (ValueError, TypeError):
                sg.popup_error("Timeout and Workers must be numbers.")
                continue

            # which labels?
            labels_to_scan = None
            if event == "Scan Selected":
                selected = values["-LIST-"]
                if not selected:
                    sg.popup("Select one or more buildings in the list.")
                    continue
                labels_to_scan = selected

            log("\nStarting scan...\n")
            worker_thread = threading.Thread(
                target=scan_worker,
                args=(PRESET_SUBNETS, labels_to_scan, timeout_ms, workers, "-OUT-", window),
                daemon=True
            )
            worker_thread.start()

    window.close()

if __name__ == "__main__":
    main()
