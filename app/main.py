"""
M-FIREWALL — Entry point de la aplicación
"""

import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from app.core.configuration import load_config
from app.constants import BLOCKED_DOMAINS, DEFAULT_CONN_PROFILES
import copy


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("M-FIREWALL")
    app.setOrganizationName("ProyectoM")

    # Cargar configuración
    config = load_config()

    # Inicializar dominios bloqueados si no existen
    if not config.get("blocked_domains"):
        config["blocked_domains"] = copy.deepcopy(BLOCKED_DOMAINS)

    # Inicializar perfiles de conexión si no existen
    if not config.get("conn_profiles"):
        config["conn_profiles"] = copy.deepcopy(DEFAULT_CONN_PROFILES)

    from app.ui.main_window import MainWindow
    window = MainWindow(config)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
