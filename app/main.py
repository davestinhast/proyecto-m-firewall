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
    En Linux: detecta interfaces WAN/LAN, IP del servidor y subred cliente
    automáticamente si no están configuradas todavía.
    En Windows: no hace nada.
    """
    from app.core.platform_detector import is_linux
    if not is_linux():
        return config

    # Solo auto-detecta si LAN no está configurada aún
    if config.get("interfaces", {}).get("lan"):
        return config

    try:
        from app.services import network_service

        own_ip, iface = network_service.get_own_ip_and_interface()
        if not own_ip or own_ip == "127.0.0.1":
            return config

        interfaces = network_service.get_available_interfaces()

        config.setdefault("interfaces", {})
        config["interfaces"]["lan"] = iface

        # WAN: primera interfaz distinta de LAN (o la misma si solo hay una)
        wan = next((i for i in interfaces if i != iface and i != "lo"), iface)
        config["interfaces"]["wan"] = wan

        config["server_ip"] = own_ip

        # Red cliente: /24 basada en IP detectada
        parts = own_ip.split(".")
        if len(parts) == 4:
            config["client_network"] = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        save_config(config)

    except Exception:
        pass  # Nunca romper el arranque

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
