"""
Lee y parsea el archivo de log de paquetes rechazados.
"""

import re
import os
from pathlib import Path
from datetime import datetime
from typing import Optional
from app.constants import LINUX_LOG_FILE

# Regex para parsear líneas del log de iptables
_LOG_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*?"
    r"PM-DROP.*?"
    r"IN=(?P<in_iface>\S*)\s+"
    r"OUT=(?P<out_iface>\S*)\s+"
    r".*?SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)\s+"
    r".*?PROTO=(?P<proto>\S+)"
    r"(?:.*?DPT=(?P<dport>\d+))?"
)


def parse_log_line(line: str) -> Optional[dict]:
    m = _LOG_PATTERN.search(line)
    if not m:
        return None
    return {
        "raw": line.strip(),
        "time": f"{m.group('month')} {m.group('day')} {m.group('time')}",
        "in_iface": m.group("in_iface"),
        "src": m.group("src"),
        "dst": m.group("dst"),
        "proto": m.group("proto"),
        "dport": m.group("dport") or "",
        "reason": _guess_reason(m.group("dst"), m.group("dport") or ""),
    }


def _guess_reason(dst: str, dport: str) -> str:
    facebook_prefixes = ("157.240.", "163.70.", "31.13.", "66.220.", "66.116.")
    youtube_prefixes = ("142.250.", "172.217.", "216.58.", "74.125.")
    hotmail_prefixes = ("40.97.", "40.99.", "13.107.", "52.109.")

    for p in facebook_prefixes:
        if dst.startswith(p):
            return "Facebook"
    for p in youtube_prefixes:
        if dst.startswith(p):
            return "YouTube"
    for p in hotmail_prefixes:
        if dst.startswith(p):
            return "Hotmail"

    if dport in ("22",):
        return "SSH bloqueado"
    if dport in ("80", "443"):
        return "Web bloqueada"
    return "Regla firewall"


def read_log_tail(n: int = 200, log_file: str = LINUX_LOG_FILE) -> list[dict]:
    """Lee las últimas n entradas del log."""
    path = Path(log_file)
    if not path.exists():
        return _demo_log_entries()

    entries = []
    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()
        for line in reversed(lines[-n * 3:]):
            parsed = parse_log_line(line)
            if parsed:
                entries.append(parsed)
                if len(entries) >= n:
                    break
    except Exception:
        pass
    return entries


def count_rejected_today(log_file: str = LINUX_LOG_FILE) -> int:
    today = datetime.now().strftime("%b %d").replace(" 0", "  ")  # "Jul  5" o "Jul 15"
    path = Path(log_file)
    if not path.exists():
        return 145  # demo
    count = 0
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                if "PM-DROP" in line and today in line:
                    count += 1
    except Exception:
        pass
    return count


def _demo_log_entries() -> list[dict]:
    now = datetime.now().strftime("%b %d %H:%M:%S")
    return [
        {"time": now, "in_iface": "eth1", "src": "192.168.50.10", "dst": "157.240.0.35",  "proto": "TCP", "dport": "443", "reason": "Facebook"},
        {"time": now, "in_iface": "eth1", "src": "192.168.50.10", "dst": "142.250.0.1",   "proto": "TCP", "dport": "443", "reason": "YouTube"},
        {"time": now, "in_iface": "eth1", "src": "192.168.50.11", "dst": "192.168.50.1",  "proto": "TCP", "dport": "22",  "reason": "SSH bloqueado"},
        {"time": now, "in_iface": "eth1", "src": "AA:BB:CC:DD:EE:02", "dst": "any",       "proto": "ARP", "dport": "",   "reason": "MAC bloqueada"},
        {"time": now, "in_iface": "eth1", "src": "192.168.50.10", "dst": "40.97.0.1",     "proto": "TCP", "dport": "80",  "reason": "Hotmail"},
    ]
