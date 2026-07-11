"""
Validaciones de entrada: IPv4, MAC, interfaz, puerto.
"""

import re
import ipaddress


def validate_ipv4(value: str) -> tuple[bool, str]:
    """Retorna (ok, mensaje)."""
    if not value or not value.strip():
        return False, "Campo requerido."
    try:
        ipaddress.IPv4Address(value.strip())
        return True, ""
    except ValueError:
        return False, f"'{value}' no es una dirección IPv4 válida."


def validate_cidr(value: str) -> tuple[bool, str]:
    if not value or not value.strip():
        return False, "Campo requerido."
    try:
        ipaddress.IPv4Network(value.strip(), strict=False)
        return True, ""
    except ValueError:
        return False, f"'{value}' no es una red CIDR válida (ej: 192.168.1.0/24)."


def validate_mac(value: str) -> tuple[bool, str]:
    pattern = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
    if not value or not value.strip():
        return False, "Campo requerido."
    if re.match(pattern, value.strip()):
        return True, ""
    return False, f"'{value}' no es una dirección MAC válida (ej: AA:BB:CC:DD:EE:FF)."


def validate_interface(value: str) -> tuple[bool, str]:
    pattern = r'^[a-zA-Z][a-zA-Z0-9@._-]{0,14}$'
    if not value or not value.strip():
        return False, "Campo requerido."
    if re.match(pattern, value.strip()):
        return True, ""
    return False, f"'{value}' no es un nombre de interfaz válido (ej: eth0, wlan0)."


def validate_port(value) -> tuple[bool, str]:
    try:
        port = int(value)
        if 1 <= port <= 65535:
            return True, ""
        return False, f"Puerto {port} fuera de rango (1-65535)."
    except (TypeError, ValueError):
        return False, f"'{value}' no es un número de puerto válido."


def validate_conn_limit(value) -> tuple[bool, str]:
    try:
        n = int(value)
        if 1 <= n <= 1000:
            return True, ""
        return False, f"Límite {n} fuera de rango (1-1000)."
    except (TypeError, ValueError):
        return False, f"'{value}' no es un número válido."


def normalize_mac(value: str) -> str:
    return value.strip().upper()


def normalize_ip(value: str) -> str:
    return value.strip()
