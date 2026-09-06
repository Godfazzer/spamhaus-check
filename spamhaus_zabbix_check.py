#!/usr/bin/env python3
"""
spamhaus_zabbix_check.py
Version: 3.0.0

Checks a list of your own IPs/CIDR ranges against Spamhaus DQS (zen.dq),
tracking membership in SBL/CSS, XBL and PBL *separately*, diffs each list
against the previous run's saved state, and pushes both an aggregate
summary and a per-list breakdown to Zabbix as trapper items via
`zabbix_sender`.

Requires the SPAMHAUS_DQS_KEY environment variable to be set - there is
no built-in default. Get your own key at https://www.spamhaus.com/product/dqs/

Designed to run in a loop inside a container on any host with network
access to Spamhaus DNS and to your Zabbix server on TCP/10051 - it does
NOT need to run on the Zabbix server itself.

State:
    --statefile points at a JSON file of:
        {ip: {"lists": ["XBL", "SBL/CSS", ...], "detail": str}}
    from the previous run. Mount its parent directory as a volume so it
    survives container restarts/recreation.

    Upgrading from a v2.x state file (which only had a "listed" boolean,
    no per-list breakdown) is safe - entries without a "lists" key are
    treated as having no prior list membership, so the first run after
    upgrading will report every currently-listed IP as "newly listed" in
    its respective list. That's expected, not a bug.

Zabbix side (create these as "Zabbix trapper" items on the host named
by --zabbix-host):

    Aggregate (any list) - unchanged from v2.x, existing items/triggers
    keep working as-is:
        spamhaus.total_checked      (Numeric unsigned)
        spamhaus.listed_count       (Numeric unsigned)
        spamhaus.new_listed_count   (Numeric unsigned)
        spamhaus.new_listed         (Text, JSON array of IPs)
        spamhaus.delisted_count     (Numeric unsigned)
        spamhaus.delisted           (Text, JSON array of IPs)

    Per-list (new in 3.0.0) - one set of six for each of sbl_css, xbl, pbl:
        spamhaus.sbl_css_listed_count      (Numeric unsigned)
        spamhaus.sbl_css_listed            (Text, JSON array of IPs)
        spamhaus.sbl_css_new_listed_count  (Numeric unsigned)
        spamhaus.sbl_css_new_listed        (Text, JSON array of IPs)
        spamhaus.sbl_css_delisted_count    (Numeric unsigned)
        spamhaus.sbl_css_delisted          (Text, JSON array of IPs)
        spamhaus.xbl_listed_count          (Numeric unsigned)
        spamhaus.xbl_listed                (Text, JSON array of IPs)
        spamhaus.xbl_new_listed_count      (Numeric unsigned)
        spamhaus.xbl_new_listed            (Text, JSON array of IPs)
        spamhaus.xbl_delisted_count        (Numeric unsigned)
        spamhaus.xbl_delisted              (Text, JSON array of IPs)
        spamhaus.pbl_listed_count          (Numeric unsigned)
        spamhaus.pbl_listed                (Text, JSON array of IPs)
        spamhaus.pbl_new_listed_count      (Numeric unsigned)
        spamhaus.pbl_new_listed            (Text, JSON array of IPs)
        spamhaus.pbl_delisted_count        (Numeric unsigned)
        spamhaus.pbl_delisted              (Text, JSON array of IPs)

Usage:
    python3 spamhaus_zabbix_check.py ips.txt \
        --statefile /data/state.json \
        --zabbix-server 10.0.0.5 \
        --zabbix-host spamhaus-monitor
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import concurrent.futures
from pathlib import Path

SCRIPT_VERSION = "3.0.0"

# No default/fallback value - the key must be supplied via environment
# variable so it never ends up baked into the script or a container image.
# Pass it with `-e SPAMHAUS_DQS_KEY=...` at container runtime.
DQS_KEY = os.environ.get("SPAMHAUS_DQS_KEY")

# Canonical list display name -> Zabbix key slug (no slash - not all
# characters are safe in a plain Zabbix item key).
LIST_KEYS = {
    "SBL/CSS": "sbl_css",
    "XBL": "xbl",
    "PBL": "pbl",
}

SBL_CSS_CODES = {"127.0.0.2", "127.0.0.3"}
XBL_CODES = {"127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7"}
PBL_CODES = {"127.0.0.10", "127.0.0.11"}


def check_spamhaus(ip):
    """Returns (clean_ip, matched_lists: set[str] subset of LIST_KEYS, detail: str)."""
    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ip)
    if not match:
        return ip, set(), "Invalid IP format"
    clean_ip = match.group(0)

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.version != 4:
            return clean_ip, set(), "Skipped (Only IPv4 supported)"
    except ValueError:
        return clean_ip, set(), "Invalid IP format"

    reversed_ip = '.'.join(reversed(clean_ip.split('.')))
    query = f"{reversed_ip}.{DQS_KEY}.zen.dq.spamhaus.net"

    try:
        answers = socket.getaddrinfo(query, None, socket.AF_INET, socket.SOCK_DGRAM)
        responses = [ans[4][0] for ans in answers]

        matched_lists = set()
        status_desc = []
        for response in responses:
            if response in SBL_CSS_CODES:
                matched_lists.add("SBL/CSS")
                status_desc.append(f"SBL/CSS ({response})")
            elif response in XBL_CODES:
                matched_lists.add("XBL")
                status_desc.append(f"XBL ({response})")
            elif response in PBL_CODES:
                matched_lists.add("PBL")
                status_desc.append(f"PBL ({response})")
            elif response.startswith("127.255.255."):
                status_desc.append(f"DNS Blocked ({response})")
            else:
                status_desc.append(f"Listed ({response})")

        status_desc = sorted(set(status_desc))
        if status_desc:
            return clean_ip, matched_lists, " + ".join(status_desc)

    except socket.gaierror:
        pass

    return clean_ip, set(), "Not Listed (Clean, Not in PBL/XBL/CSS)"


def load_ips(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]

    ips = []
    for line in lines:
        if '/' in line:
            try:
                net = ipaddress.ip_network(line, strict=False)
                for ip in net:
                    ips.append(str(ip))
            except ValueError:
                print(f"Попередження: недійсний формат мережі {line}")
        else:
            ips.append(line)
    return ips


def load_previous_state(statefile: Path) -> dict:
    if not statefile.exists():
        return {}
    try:
        return json.loads(statefile.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(statefile: Path, state: dict) -> None:
    statefile.parent.mkdir(parents=True, exist_ok=True)
    statefile.write_text(json.dumps(state, indent=2))


def zabbix_send(server: str, host: str, key: str, value) -> None:
    """Push a single trapper value via the zabbix_sender binary."""
    payload = json.dumps(value) if isinstance(value, (list, dict)) else str(value)
    try:
        result = subprocess.run(
            ["zabbix_sender", "-z", server, "-s", host, "-k", key, "-o", payload],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            print(f"[zabbix_sender] warning sending {key}: {result.stdout} {result.stderr}", file=sys.stderr)
    except FileNotFoundError:
        print("[zabbix_sender] binary not found - is zabbix-sender installed in the container?", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print(f"[zabbix_sender] timed out sending {key}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check IPs against Spamhaus DQS, diff vs last run, push to Zabbix.")
    parser.add_argument("ip_file", help="File of IPs/CIDR ranges to check.")
    parser.add_argument("--statefile", required=True, help="Path to JSON file storing previous run's per-IP status.")
    parser.add_argument("--zabbix-server", help="Zabbix server/proxy address. If omitted, results are only printed.")
    parser.add_argument("--zabbix-host", help="Host name as configured in Zabbix (required if --zabbix-server is set).")
    parser.add_argument("--workers", type=int, default=20, help="Concurrent DNS lookups (default: 20).")
    args = parser.parse_args()

    if args.zabbix_server and not args.zabbix_host:
        parser.error("--zabbix-host is required when --zabbix-server is set")

    if not DQS_KEY:
        print("Error: SPAMHAUS_DQS_KEY environment variable is not set. "
              "Pass it with -e SPAMHAUS_DQS_KEY=... at container runtime.", file=sys.stderr)
        return 2

    try:
        ips = load_ips(args.ip_file)
    except FileNotFoundError:
        print(f"Помилка: Файл {args.ip_file} не знайдено.")
        return 1

    print(f"Перевірка {len(ips)} IP-адрес через Spamhaus DQS DNS...")
    print("-" * 65)
    print(f"{'IP-адреса':<18} | {'Статус (DQS)'}")
    print("-" * 65)

    current_state = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        for clean_ip, matched_lists, detail in executor.map(check_spamhaus, ips):
            print(f"{clean_ip:<18} | {detail}")
            current_state[clean_ip] = {"lists": sorted(matched_lists), "detail": detail}
    print("-" * 65)

    statefile = Path(args.statefile)
    previous_state = load_previous_state(statefile)

    # Aggregate (any of the 3 lists) - keeps existing v2.x items/triggers working unchanged.
    current_any = {ip for ip, info in current_state.items() if info.get("lists")}
    previous_any = {ip for ip, info in previous_state.items() if info.get("lists")}
    newly_listed = sorted(current_any - previous_any)
    newly_delisted = sorted(previous_any - current_any)
    listed_count = len(current_any)

    # Per-list breakdown (new in 3.0.0).
    per_list_metrics = {}
    for display_name, key_slug in LIST_KEYS.items():
        current_set = {ip for ip, info in current_state.items() if display_name in info.get("lists", [])}
        previous_set = {ip for ip, info in previous_state.items() if display_name in info.get("lists", [])}
        nl = sorted(current_set - previous_set)
        nd = sorted(previous_set - current_set)
        per_list_metrics[key_slug] = {
            "listed": sorted(current_set),
            "listed_count": len(current_set),
            "new_listed": nl,
            "new_listed_count": len(nl),
            "delisted": nd,
            "delisted_count": len(nd),
        }

    save_state(statefile, current_state)

    print(f"Script version: {SCRIPT_VERSION}")
    print(f"Newly listed (any list):   {newly_listed}")
    print(f"Newly delisted (any list): {newly_delisted}")
    print("-" * 65)
    for display_name, key_slug in LIST_KEYS.items():
        m = per_list_metrics[key_slug]
        print(f"{display_name}: listed={m['listed_count']} new={m['new_listed_count']} delisted={m['delisted_count']}")
        if m["new_listed"]:
            print(f"  new:      {m['new_listed']}")
        if m["delisted"]:
            print(f"  delisted: {m['delisted']}")

    if args.zabbix_server:
        metrics = {
            "spamhaus.total_checked": len(current_state),
            "spamhaus.listed_count": listed_count,
            "spamhaus.new_listed_count": len(newly_listed),
            "spamhaus.new_listed": newly_listed,
            "spamhaus.delisted_count": len(newly_delisted),
            "spamhaus.delisted": newly_delisted,
        }
        for key_slug, m in per_list_metrics.items():
            metrics[f"spamhaus.{key_slug}_listed"] = m["listed"]
            metrics[f"spamhaus.{key_slug}_listed_count"] = m["listed_count"]
            metrics[f"spamhaus.{key_slug}_new_listed"] = m["new_listed"]
            metrics[f"spamhaus.{key_slug}_new_listed_count"] = m["new_listed_count"]
            metrics[f"spamhaus.{key_slug}_delisted"] = m["delisted"]
            metrics[f"spamhaus.{key_slug}_delisted_count"] = m["delisted_count"]

        for key, value in metrics.items():
            zabbix_send(args.zabbix_server, args.zabbix_host, key, value)

    return 0


if __name__ == "__main__":
    sys.exit(main())