"""
M-FIREWALL — Entry point de la aplicación
"""

import sys
import copy
from .core.configuration import load_config, save_config
from .constants import BLOCKED_DOMAINS, DEFAULT_CONN_PROFILES

# Versión del esquema de config — incrementar cuando cambien los defaults
CONFIG_SCHEMA_VERSION = 3


def _apply_defaults(config: dict) -> dict:
    """
    Si el config guardado es de una versión anterior, resetea a defaults.
    """
    saved_version = config.get("_schema_version", 0)
    changed = False

    if saved_version < CONFIG_SCHEMA_VERSION:
        config["blocked_domains"] = copy.deepcopy(BLOCKED_DOMAINS)
        config["conn_profiles"]   = copy.deepcopy(DEFAULT_CONN_PROFILES)
        config["_schema_version"] = CONFIG_SCHEMA_VERSION
        changed = True

    if not config.get("blocked_domains"):
        config["blocked_domains"] = copy.deepcopy(BLOCKED_DOMAINS)
        changed = True
    if not config.get("conn_profiles"):
        config["conn_profiles"] = copy.deepcopy(DEFAULT_CONN_PROFILES)
        changed = True

    # Mantiene las casillas del usuario, pero actualiza listas de dominios
    # cuando el proyecto aprende nuevos endpoints/CDN.
    for key, defaults in BLOCKED_DOMAINS.items():
        current = config.setdefault("blocked_domains", {}).setdefault(key, copy.deepcopy(defaults))
        current.setdefault("label", defaults.get("label", key))
        current.setdefault("description", defaults.get("description", ""))
        current.setdefault("enabled", defaults.get("enabled", False))
        known_domains = current.setdefault("domains", [])
        for domain in defaults.get("domains", []):
            if domain not in known_domains:
                known_domains.append(domain)
                changed = True

    if changed:
        save_config(config)

    return config


def _auto_detect_network(config: dict) -> dict:
    """
    En Linux: detecta WAN (salida a internet), LAN (hacia clientes) e IP del servidor
    automáticamente si no están configuradas todavía.
    WAN = interfaz con ruta por defecto (hacia internet).
    LAN = segunda interfaz (hacia los clientes).
    """
    from app.core.platform_detector import is_linux
    if not is_linux():
        return config

    # Solo auto-detecta si aún no hay configuración de interfaces
    if config.get("interfaces", {}).get("lan"):
        return config

    try:
        from app.services.network_service import detect_wan_lan_ip

        wan, lan, server_ip = detect_wan_lan_ip()
        if not server_ip or server_ip == "127.0.0.1":
            return config

        config.setdefault("interfaces", {})
        config["interfaces"]["wan"] = wan   # salida a internet
        config["interfaces"]["lan"] = lan   # hacia clientes
        config["server_ip"] = server_ip

        parts = server_ip.split(".")
        if len(parts) == 4:
            config["client_network"] = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        save_config(config)

    except Exception:
        pass  # nunca romper el arranque

    return config


def main():
    from PySide6.QtWidgets import QApplication
    app = QApplication(sys.argv)
    app.setApplicationName("M-FIREWALL")
    app.setOrganizationName("ProyectoM")

    config = load_config()
    config = _apply_defaults(config)
    config = _auto_detect_network(config)   # ← auto-detecta red al arrancar

    # Iniciar servidor DNS Proxy en segundo plano
    try:
        from app.services.dns_proxy_service import get_dns_proxy
        get_dns_proxy().start(config)
    except Exception:
        pass

    from app.ui.main_window import MainWindow
    window = MainWindow(config)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
