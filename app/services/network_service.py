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


# Tabla OUI mínima — primeros 6 dígitos hex del MAC → fabricante
_OUI_TABLE: dict[str, str] = {
    "00:50:56": "VMware",     "00:0C:29": "VMware",     "00:1C:14": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "AC:DE:48": "Apple",      "00:1A:11": "Apple",      "F4:5C:89": "Apple",
    "3C:22:FB": "Apple",      "A8:51:AB": "Apple",      "DC:2B:2A": "Apple",
    "00:1F:3B": "Intel",      "00:1B:21": "Intel",      "48:51:B7": "Intel",
    "F8:75:A4": "Intel",      "8C:8D:28": "Intel",      "A4:C3:F0": "Intel",
    "00:1A:2B": "Cisco",      "00:1E:13": "Cisco",      "28:AC:9E": "Cisco",
    "00:23:AB": "Samsung",    "00:26:37": "Samsung",     "94:8B:C1": "Samsung",
    "F4:7B:5E": "Samsung",    "8C:77:12": "Samsung",
    "00:26:18": "Realtek",    "10:02:B5": "Realtek",
    "FC:EC:DA": "Ubiquiti",   "00:27:22": "Ubiquiti",   "44:D9:E7": "Ubiquiti",
    "00:0F:E2": "TP-Link",    "50:BD:5F": "TP-Link",    "C4:6E:1F": "TP-Link",
    "74:DA:38": "Edimax",     "00:90:4C": "Epigram",
    "00:11:22": "Asix",       "00:50:C2": "Bosch",
    "B8:27:EB": "Raspberry",  "DC:A6:32": "Raspberry",  "E4:5F:01": "Raspberry",
    "00:25:9C": "Cisco-Linksys", "20:AA:4B": "Cisco-Linksys",
}


def _lookup_oui(mac: str) -> str:
    """Busca fabricante por los primeros 3 octetos del MAC."""
    prefix = mac[:8].upper()
    return _OUI_TABLE.get(prefix, "")


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
                if mac == "00:00:00:00:00:00":
                    continue
                hostname = _resolve_hostname(ip)
                vendor = _lookup_oui(mac)
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": vendor,
                    "status": "conocido",
                })
    except Exception:
        pass
    return devices


def _resolve_hostname(ip: str) -> str:
    """
    Intenta resolver el hostname por varios métodos:
    1. nmblookup (NetBIOS — funciona con PCs Windows en la misma LAN)
    2. avahi-resolve-address (mDNS — funciona con Linux/Mac)
    3. socket.gethostbyaddr (DNS inverso — fallback, rara vez funciona en labs)
    """
    # --- nmblookup (Windows NetBIOS) ---
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=2
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            # Líneas de formato: "        NOMBRE         <00> -         B <ACTIVE>"
            if "<00>" in line and "<GROUP>" not in line:
                name = line.split("<00>")[0].strip()
                if name and name != ip:
                    return name
    except Exception:
        pass

    # --- avahi-resolve (mDNS Linux/Mac) ---
    try:
        result = subprocess.run(
            ["avahi-resolve-address", ip],
            capture_output=True, text=True, timeout=2
        )
        out = result.stdout.strip()
        if out:
            parts = out.split()
            if len(parts) >= 2:
                hostname = parts[1].rstrip(".")
                if hostname and hostname != ip:
                    return hostname
    except Exception:
        pass

    # --- DNS inverso con timeout corto ---
    import threading

    result_holder = [""]

    def _dns_lookup():
        try:
            result_holder[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    t = threading.Thread(target=_dns_lookup, daemon=True)
    t.start()
    t.join(timeout=1.0)
    return result_holder[0]


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


def detect_wan_lan_ip() -> tuple[str, str, str]:
    """
    Detecta automáticamente WAN, LAN y la IP del servidor Kali en la LAN.
    Retorna (wan_iface, lan_iface, server_ip).
    WAN = interfaz con ruta por defecto hacia internet.
    LAN = segunda interfaz (hacia clientes).
    server_ip = IP de Kali en la interfaz LAN.
    """
    if platform.system() == "Windows":
        return "eth0", "eth1", "192.168.50.1"

    wan = ""
    try:
        r = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if line.startswith("default"):
                m = re.search(r"dev\s+(\S+)", line)
                if m:
                    wan = m.group(1)
                    break
    except Exception:
        pass

    # LAN = cualquier interfaz que no sea lo, wan, docker, virbr, etc.
    _skip = {"lo", wan}
    _skip_prefix = ("docker", "br-", "virbr", "veth", "tun", "tap")
    all_ifaces = get_available_interfaces()
    candidates = [
        i for i in all_ifaces
        if i not in _skip and not any(i.startswith(p) for p in _skip_prefix)
    ]
    lan = candidates[0] if candidates else (wan or "eth1")

    # IP del servidor en la interfaz LAN
    server_ip = ""
    try:
        r = subprocess.run(
            ["ip", "-4", "addr", "show", lan],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", r.stdout)
        if m:
            server_ip = m.group(1)
    except Exception:
        pass

    # Fallback: usar la IP con ruta al exterior
    if not server_ip:
        server_ip, _ = get_own_ip_and_interface()

    return wan or "eth0", lan, server_ip
