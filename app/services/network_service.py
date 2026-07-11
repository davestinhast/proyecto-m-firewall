"""
Escanea la red local y detecta dispositivos conectados.
Detecta IP propia e interfaz de red.
"""

import socket
import subprocess
import platform
import re
from typing import Optional
import ipaddress


def get_own_ip_and_interface() -> tuple[str, str]:
    """Retorna (ip, interfaz). Usa el gateway por defecto."""
    try:
        # Conectar a DNS de Google para detectar IP saliente
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        iface = _get_interface_for_ip(ip)
        return ip, iface
    except Exception:
        return "127.0.0.1", "lo"


def _get_interface_for_ip(target_ip: str) -> str:
    """Identifica interfaz asociada a una IP."""
    if platform.system() == "Windows":
        return "eth0"
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=5
        )
        match = re.search(r"dev\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass
    return "eth0"


def get_subnet(ip: str, prefix: int = 24) -> str:
    """192.168.1.5 → 192.168.1.0/24"""
    try:
        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        return str(net)
    except Exception:
        return f"{ip}/24"


def scan_network_arp(subnet: str) -> list[dict]:
    """
    Escaneo ARP de la red local.
    Retorna lista de dicts: {ip, mac, hostname, status}

    En Windows retorna datos demo.
    En Linux usa arp-scan o nmap o tabla ARP.
    """
    if platform.system() == "Windows":
        return _demo_devices()

    # Intentar arp-scan
    devices = _scan_with_arpscan(subnet)
    if devices:
        return devices

    # Fallback: leer tabla ARP del sistema
    devices = _read_arp_table()
    return devices


def _scan_with_arpscan(subnet: str) -> list[dict]:
    try:
        result = subprocess.run(
            ["arp-scan", "--localnet", "--quiet"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return []
        return _parse_arpscan_output(result.stdout)
    except FileNotFoundError:
        return []
    except Exception:
        return []


def _parse_arpscan_output(output: str) -> list[dict]:
    devices = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            ip = parts[0].strip()
            mac = parts[1].strip().upper()
            vendor = parts[2].strip() if len(parts) > 2 else ""
            hostname = _resolve_hostname(ip)
            try:
                ipaddress.IPv4Address(ip)
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": vendor,
                    "status": "activo",
                })
            except Exception:
                pass
    return devices


def _read_arp_table() -> list[dict]:
    """Lee /proc/net/arp para obtener dispositivos conocidos."""
    devices = []
    try:
        with open("/proc/net/arp") as f:
            lines = f.readlines()[1:]  # saltar encabezado
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                mac = parts[3].upper()
                iface = parts[5] if len(parts) > 5 else ""
                if mac == "00:00:00:00:00:00":
                    continue
                hostname = _resolve_hostname(ip)
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": "",
                    "status": "conocido",
                })
    except Exception:
        pass
    return devices


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _demo_devices() -> list[dict]:
    return [
        {"ip": "192.168.50.1",  "mac": "AA:BB:CC:DD:EE:01", "hostname": "kali-linux",     "vendor": "VMware",  "status": "activo"},
        {"ip": "192.168.50.10", "mac": "AA:BB:CC:DD:EE:02", "hostname": "DESKTOP-WIN11",  "vendor": "Intel",   "status": "activo"},
        {"ip": "192.168.50.11", "mac": "AA:BB:CC:DD:EE:03", "hostname": "android-phone",  "vendor": "Samsung", "status": "activo"},
        {"ip": "192.168.50.12", "mac": "AA:BB:CC:DD:EE:04", "hostname": "laptop-ubuntu",  "vendor": "Realtek", "status": "activo"},
    ]


def get_available_interfaces() -> list[str]:
    """Lista interfaces de red (Linux)."""
    if platform.system() == "Windows":
        return ["eth0", "eth1", "wlan0"]
    try:
        import os
        return sorted(os.listdir("/sys/class/net"))
    except Exception:
        return ["eth0", "eth1"]
