"""
Resuelve dominios a IPs y gestiona los conjuntos IPSET.
"""

import socket
import json
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def resolve_domain(domain: str) -> list[str]:
    """Retorna lista de IPs para un dominio."""
    ips = set()
    # método 1: socket estándar
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        for r in results:
            ips.add(r[4][0])
    except Exception:
        pass
    # método 2: dnspython si está disponible
    if HAS_DNSPYTHON:
        try:
            answers = dns.resolver.resolve(domain, "A")
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
    result: dict[str, list[str]] = {}
    items = [(k, v) for k, v in blocked_domains.items() if v.get("enabled", False)]
    total = len(items)

    for idx, (key, cfg) in enumerate(items):
        domains = cfg.get("domains", [])
        ips: set[str] = set()
        for domain in domains:
            found = resolve_domain(domain)
            ips.update(found)
        result[key] = sorted(ips)
        if progress_cb:
            progress_cb(idx + 1, total, key, len(result[key]))

    return result


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


def build_ipset_file(resolved: dict[str, list[str]]) -> str:
    """Genera contenido del archivo .ipset para ipset restore."""
    lines = [
        "# M-FIREWALL — conjuntos IPSET",
        f"# Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    for key, ips in resolved.items():
        set_name = f"PM_{key.upper()}"
        lines.append(f"create {set_name} hash:ip family inet hashsize 1024 maxelem 65536 -exist")
        lines.append(f"flush {set_name}")
        for ip in ips:
            lines.append(f"add {set_name} {ip}")
        lines.append("")
    return "\n".join(lines)
