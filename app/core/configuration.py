"""
Carga y guarda la configuración del proyecto en JSON.
Usa la ruta de Linux si existe, si no, usa una ruta local.
"""

import json
import os
import copy
from pathlib import Path
from app.core.platform_detector import is_linux

_DEFAULT_CONFIG = {
    "interfaces": {
        "wan": "",
        "lan": ""
    },
    "server_ip": "",
    "client_network": "",
    "rules_file": "/opt/proyecto-m/rules/project_m.rules.v4",
    "log_dir": "/var/log/proyecto-m",
    "log_file": "/var/log/proyecto-m/iptables-rejected.log",
    "domain_refresh_interval": 3600,
    "auto_load_on_boot": False,
    "default_action": "DROP",
    "blocked_domains": {},
    "mac_rules": [],
    "conn_profiles": [],
    "clisrv": {
        "enabled": False,
        "server_ip": "",
        "client_ip": "",
        "interface": "",
        "protocols": ["tcp", "udp", "icmp"],
        "action": "DROP"
    }
}


def _get_config_path() -> Path:
    if is_linux():
        linux_path = Path("/opt/proyecto-m/config/project_m.json")
        # Intentar crear el directorio si no existe y somos root
        if not linux_path.parent.exists():
            try:
                linux_path.parent.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                pass  # No somos root, usar fallback local
        if linux_path.parent.exists():
            return linux_path
    # Fallback: directorio local junto al repo (funciona en Windows y Linux sin root)
    base = Path(__file__).resolve().parent.parent.parent
    local_path = base / "config" / "project_m.json"
    local_path.parent.mkdir(parents=True, exist_ok=True)
    return local_path


def load_config() -> dict:
    path = _get_config_path()
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # merge con defaults para campos faltantes
            merged = copy.deepcopy(_DEFAULT_CONFIG)
            _deep_update(merged, data)
            return merged
        except Exception:
            pass
    return copy.deepcopy(_DEFAULT_CONFIG)


def save_config(config: dict) -> bool:
    path = _get_config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def get_default_config() -> dict:
    return copy.deepcopy(_DEFAULT_CONFIG)


def _deep_update(base: dict, override: dict):
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_update(base[k], v)
        else:
            base[k] = v
