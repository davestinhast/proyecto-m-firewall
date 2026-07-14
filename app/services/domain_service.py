"""
Resuelve dominios a IPs y gestiona los conjuntos IPSET.

Los sets de ipset (PM_FACEBOOK, PM_YOUTUBE, PM_HOTMAIL) permiten
actualizar las IPs bloqueadas sin necesidad de recargar iptables,
lo que es esencial ya que los CDN de estos sitios cambian constantemente.
"""

import socket
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from app.constants import IPSET_SET_PREFIX


def resolve_domain(domain: str) -> list[str]:
    """Retorna lista de IPs para un dominio usando multiples resolvidores publicos."""
    ips = set()

    # 1. Resolver con el resolver por defecto del sistema
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        for r in results:
            ips.add(r[4][0])
    except Exception:
        pass

    # 2. Resolver consultando servidores DNS publicos populares (para capturar IPs balanceadas por CDN)
    if HAS_DNSPYTHON:
        # Consultar varios servidores para obtener una lista mas completa
        dns_servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"]
        for ns in dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [ns]
                resolver.timeout = 1.5
                resolver.lifetime = 1.5
                answers = resolver.resolve(domain, "A")
                for rdata in answers:
                    ips.add(str(rdata))
            except Exception:
                pass

    return sorted(ips)


def resolve_all_domains(blocked_domains: dict, progress_cb: Optional[Callable] = None) -> dict[str, list[str]]:
    """
    Resuelve todos los dominios habilitados.
    Retorna {"facebook": ["157.240.0.1", ...], ...}
    """
    # IPs de respaldo en caso de fallo en la resolucion DNS dinamica
    fallback_ips = {
        "facebook": [
            "157.240.22.35", "157.240.2.35", "31.13.65.36", "31.13.71.36", 
            "31.13.77.35", "157.240.1.35", "31.13.67.35", "157.240.18.35"
        ],
        "youtube": [
            "142.250.78.142", "142.250.217.78", "172.217.171.206", "172.217.171.142",
            "172.217.171.238", "142.250.200.78", "142.250.201.78", "142.250.190.14"
        ],
        "hotmail": [
            "13.107.21.200", "13.107.246.40", "204.79.197.200", "40.97.120.42",
            "40.97.148.226", "40.97.156.114", "52.96.165.18", "52.96.184.210"
        ]
    }

    result: dict[str, list[str]] = {}
    items = [(k, v) for k, v in blocked_domains.items() if v.get("enabled", False)]
    total = len(items)

    for idx, (key, cfg) in enumerate(items):
        domains = cfg.get("domains", [])
        ips: set[str] = set()
        for domain in domains:
            found = resolve_domain(domain)
            ips.update(found)
        
        # Si la resolucion dinamica fallo por completo, usar IPs de respaldo
        resolved_list = sorted(ips)
        if not resolved_list and key in fallback_ips:
            resolved_list = fallback_ips[key]

        result[key] = resolved_list
        if progress_cb:
            progress_cb(idx + 1, total, key, len(result[key]))

    return result


def _is_valid_ipv4(ip: str) -> bool:
    """Valida si una cadena es una direccion IPv4 sintacticamente correcta."""
    if not ip or not isinstance(ip, str):
        return False
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def build_ipset_file(resolved: dict[str, list[str]]) -> str:
    """Genera contenido del archivo .ipset para ipset restore."""
    lines = [
        "# M-FIREWALL — conjuntos IPSET",
        f"# Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# Cargar con: ipset restore < project_m.ipset",
        "",
    ]
    for key, ips in resolved.items():
        set_name = f"{IPSET_SET_PREFIX}{key.upper()}"
        lines.append(f"create {set_name} hash:ip family inet hashsize 1024 maxelem 65536 -exist")
        lines.append(f"flush {set_name}")
        for ip in ips:
            if _is_valid_ipv4(ip):
                lines.append(f"add {set_name} {ip.strip()}")
        lines.append("")
    return "\n".join(lines)


def apply_ipset(resolved: dict[str, list[str]]) -> tuple[bool, str]:
    """
    Aplica los sets de ipset directamente mediante 'ipset restore'.
    Crea o actualiza PM_FACEBOOK, PM_YOUTUBE, PM_HOTMAIL con las IPs actuales.
    Retorna (ok, mensaje).
    """
    if not resolved:
        return True, "No hay sitios habilitados para bloquear con ipset."

    ipset_content = build_ipset_file(resolved)

    try:
        result = subprocess.run(
            ["ipset", "restore"],
            input=ipset_content,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            total_ips = sum(len(ips) for ips in resolved.values())
            sets_str = ", ".join(
                f"{IPSET_SET_PREFIX}{k.upper()} ({len(v)} IPs)"
                for k, v in resolved.items()
            )
            return True, f"ipset actualizado: {sets_str}"
        else:
            return False, f"Error en ipset restore: {result.stderr.strip()}"
    except FileNotFoundError:
        return False, "ipset no está instalado. Ejecuta: apt-get install ipset"
    except subprocess.TimeoutExpired:
        return False, "Timeout al ejecutar ipset restore."
    except Exception as e:
        return False, f"Error inesperado en ipset: {e}"


def save_resolved_ips(resolved: dict[str, list[str]], cache_path: str) -> bool:
    """Guarda IPs resueltas en JSON para caché."""
    try:
        data = {
            "timestamp": datetime.now().isoformat(),
            "resolved": resolved,
        }
        p = Path(cache_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception:
        return False


def load_resolved_ips(cache_path: str) -> tuple[Optional[dict], Optional[str]]:
    """Carga IPs desde caché. Retorna (resolved_dict, timestamp)."""
    try:
        p = Path(cache_path)
        if not p.exists():
            return None, None
        with open(p) as f:
            data = json.load(f)
        return data.get("resolved", {}), data.get("timestamp")
    except Exception:
        return None, None
