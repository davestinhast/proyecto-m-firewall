"""
M-FIREWALL — Entry point de la aplicación
"""

import sys
import copy
from PySide6.QtWidgets import QApplication
from app.core.configuration import load_config, save_config
from app.constants import BLOCKED_DOMAINS, DEFAULT_CONN_PROFILES

# Versión del esquema de config — incrementar cuando cambien los defaults
CONFIG_SCHEMA_VERSION = 2


def _apply_defaults(config: dict) -> dict:
    """
    Si el config guardado es de una versión anterior (sin _schema_version
    o con versión menor), sobreescribe los dominios y perfiles con los
    defaults actuales (todo desactivado).
    """
    saved_version = config.get("_schema_version", 0)

    if saved_version < CONFIG_SCHEMA_VERSION:
        # Reset dominios — todo desactivado
        config["blocked_domains"] = copy.deepcopy(BLOCKED_DOMAINS)
        # Reset perfiles connlimit — todo desactivado
        config["conn_profiles"] = copy.deepcopy(DEFAULT_CONN_PROFILES)
        config["_schema_version"] = CONFIG_SCHEMA_VERSION
        save_config(config)

    # Garantizar que existen aunque sea versión actual
    if not config.get("blocked_domains"):
        config["blocked_domains"] = copy.deepcopy(BLOCKED_DOMAINS)
    if not config.get("conn_profiles"):
        config["conn_profiles"] = copy.deepcopy(DEFAULT_CONN_PROFILES)

    return config


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("M-FIREWALL")
    app.setOrganizationName("ProyectoM")

    config = load_config()
    config = _apply_defaults(config)

    from app.ui.main_window import MainWindow
    window = MainWindow(config)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
