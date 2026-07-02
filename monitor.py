"""
Network Guardian - Violation Monitor
-------------------------------------
Watches Pi-hole's query database for devices repeatedly trying to reach
blocked (illegal/adult/malware) domains, and flags them as violators.

This script does NOT disconnect devices automatically. Auto-disconnecting
a device requires either ARP spoofing or deauthentication packets, which
are network-attack techniques even on your own network and are not
something this project implements. Instead, when a device is flagged,
this script logs it and prints the device's IP/hostname so you can block
it in two clicks via your router's own "Parental Controls" / "Access
Control" / "Device Manager" page (every modern consumer router has one).

Run with:
    python monitor.py
"""

import json
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

# ----------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------

# Path to Pi-hole's FTL database (adjust if your Docker volume path differs)
DB_PATH = "./etc-pihole/pihole-FTL.db"

# How often to check for new violations (seconds)
POLL_INTERVAL = 30

# A client is flagged if they hit this many blocked domains within the window
VIOLATION_THRESHOLD = 5
VIOLATION_WINDOW_SECONDS = 600  # 10 minutes

VIOLATIONS_LOG = "violations.json"

# Pi-hole FTL "status" codes that mean the query was BLOCKED
# (see https://docs.pi-hole.net/ftldns/database/ for the full table)
BLOCKED_STATUSES = {1, 4, 5, 6, 7, 8, 9, 10, 11}


# ----------------------------------------------------------------------
# STATE
# ----------------------------------------------------------------------

# client_ip -> deque of timestamps of blocked queries
recent_blocks = defaultdict(deque)
flagged_clients = {}
last_seen_timestamp = int(time.time())


def load_violations():
    if Path(VIOLATIONS_LOG).exists():
        with open(VIOLATIONS_LOG, "r") as f:
            return json.load(f)
    return []


def save_violation(entry):
    data = load_violations()
    data.append(entry)
    with open(VIOLATIONS_LOG, "w") as f:
        json.dump(data, f, indent=2)


def fetch_new_blocked_queries(conn, since_ts):
    """Return rows (client, domain, timestamp) for blocked queries since since_ts."""
    placeholders = ",".join("?" for _ in BLOCKED_STATUSES)
    query = f"""
        SELECT client, domain, timestamp, status
        FROM queries
        WHERE timestamp > ?
          AND status IN ({placeholders})
        ORDER BY timestamp ASC
    """
    cur = conn.cursor()
    cur.execute(query, (since_ts, *BLOCKED_STATUSES))
    return cur.fetchall()


def check_violations():
    global last_seen_timestamp

    if not Path(DB_PATH).exists():
        print(f"[!] Pi-hole database not found at {DB_PATH}. "
              f"Check that Pi-hole is running and the path is correct.")
        return

    conn = sqlite3.connect(DB_PATH)
    rows = fetch_new_blocked_queries(conn, last_seen_timestamp)
    conn.close()

    if not rows:
        return

    now = time.time()
    for client, domain, ts, status in rows:
        dq = recent_blocks[client]
        dq.append(ts)

        # drop entries outside the rolling window
        while dq and dq[0] < now - VIOLATION_WINDOW_SECONDS:
            dq.popleft()

        if len(dq) >= VIOLATION_THRESHOLD and client not in flagged_clients:
            flagged_clients[client] = now
            entry = {
                "client_ip": client,
                "blocked_attempts_in_window": len(dq),
                "last_domain": domain,
                "flagged_at": datetime.now().isoformat(timespec="seconds"),
            }
            save_violation(entry)
            print("=" * 60)
            print(f"[VIOLATION] Device {client} hit {len(dq)} blocked sites "
                  f"in the last {VIOLATION_WINDOW_SECONDS // 60} minutes.")
            print(f"  Most recent blocked domain: {domain}")
            print("  --> Open your router's admin page (usually 192.168.1.1 "
                  "or 192.168.0.1), find 'Parental Controls' / 'Access Control' "
                  "/ 'Device Manager', and block this device's MAC address.")
            print("=" * 60)

        last_seen_timestamp = max(last_seen_timestamp, ts)

    # allow re-flagging after a cool-down so repeat offenders show up again
    cooldown = 3600
    for client in list(flagged_clients):
        if now - flagged_clients[client] > cooldown:
            del flagged_clients[client]


if __name__ == "__main__":
    print("Network Guardian monitor started. Watching Pi-hole query log...")
    print(f"Threshold: {VIOLATION_THRESHOLD} blocked attempts / "
          f"{VIOLATION_WINDOW_SECONDS // 60} min triggers a flag.\n")
    while True:
        try:
            check_violations()
        except Exception as e:
            print(f"[error] {e}")
        time.sleep(POLL_INTERVAL)
