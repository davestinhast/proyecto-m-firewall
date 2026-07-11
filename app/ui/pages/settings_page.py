"""
Pantalla 8 — Configuración general
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QLineEdit, QComboBox,
    QSpinBox, QFormLayout, QFileDialog,
)
from PySide6.QtCore import Qt, Signal
from app.core import validators
from app.services import network_service
from app.constants import LINUX_RULES_FILE, LINUX_LOG_FILE


class SettingsPage(QWidget):
    config_changed = Signal(dict)

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._load_config()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(20)

        title = QLabel("Configuración")
        title.setObjectName("label_title")
        layout.addWidget(title)

        layout.addWidget(self._build_network_card())
        layout.addWidget(self._build_paths_card())
        layout.addWidget(self._build_behavior_card())

        layout.addStretch()
        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def _build_network_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        subtitle = QLabel("Red")
        subtitle.setObjectName("label_subtitle")
        layout.addWidget(subtitle)

        form = QFormLayout()
        form.setSpacing(10)

        ifaces = network_service.get_available_interfaces()

        self._wan_combo = QComboBox()
        self._wan_combo.addItems(ifaces)
        self._lan_combo = QComboBox()
        self._lan_combo.addItems(ifaces)

        self._server_ip_input = QLineEdit()
        self._server_ip_input.setPlaceholderText("ej: 192.168.50.1")
        self._client_net_input = QLineEdit()
        self._client_net_input.setPlaceholderText("ej: 192.168.50.0/24")

        form.addRow("Interfaz WAN (salida a Internet):", self._wan_combo)
        form.addRow("Interfaz LAN (hacia clientes):", self._lan_combo)
        form.addRow("IP del servidor (Kali):", self._server_ip_input)
        form.addRow("Red del cliente (CIDR):", self._client_net_input)
        layout.addLayout(form)

        self._net_error = QLabel("")
        self._net_error.setStyleSheet("color: #D95C5C; font-size: 12px;")
        layout.addWidget(self._net_error)

        btn_row = QHBoxLayout()
        btn_save = QPushButton("Guardar")
        btn_save.setObjectName("btn_primary")
        btn_save.clicked.connect(self._save_network)
        btn_row.addWidget(btn_save)

        btn_detect = QPushButton("Detectar automáticamente")
        btn_detect.setObjectName("btn_secondary")
        btn_detect.clicked.connect(self._auto_detect)
        btn_row.addWidget(btn_detect)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return frame

    def _build_paths_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        subtitle = QLabel("Rutas de archivos")
        subtitle.setObjectName("label_subtitle")
        layout.addWidget(subtitle)

        form = QFormLayout()
        form.setSpacing(10)

        self._rules_path_input = QLineEdit()
        self._rules_path_input.setPlaceholderText(LINUX_RULES_FILE)

        self._log_path_input = QLineEdit()
        self._log_path_input.setPlaceholderText(LINUX_LOG_FILE)

        form.addRow("Archivo de reglas personalizado:", self._rules_path_input)
        form.addRow("Archivo de logs rechazados:", self._log_path_input)
        layout.addLayout(form)

        btn_row = QHBoxLayout()
        btn_save_paths = QPushButton("Guardar rutas")
        btn_save_paths.setObjectName("btn_primary")
        btn_save_paths.clicked.connect(self._save_paths)
        btn_row.addWidget(btn_save_paths)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return frame

    def _build_behavior_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        subtitle = QLabel("Comportamiento")
        subtitle.setObjectName("label_subtitle")
        layout.addWidget(subtitle)

        form = QFormLayout()
        form.setSpacing(10)

        self._refresh_spin = QSpinBox()
        self._refresh_spin.setRange(300, 86400)
        self._refresh_spin.setValue(3600)
        self._refresh_spin.setSuffix(" segundos")

        self._action_combo = QComboBox()
        self._action_combo.addItems(["DROP", "REJECT"])

        form.addRow("Intervalo de actualización de IPs:", self._refresh_spin)
        form.addRow("Acción predeterminada:", self._action_combo)
        layout.addLayout(form)

        btn_row = QHBoxLayout()
        btn_save = QPushButton("Guardar comportamiento")
        btn_save.setObjectName("btn_primary")
        btn_save.clicked.connect(self._save_behavior)
        btn_row.addWidget(btn_save)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return frame

    def _load_config(self):
        cfg = self._config
        ifaces = network_service.get_available_interfaces()
        wan = cfg.get("interfaces", {}).get("wan", "")
        lan = cfg.get("interfaces", {}).get("lan", "")
        if wan in ifaces:
            self._wan_combo.setCurrentText(wan)
        if lan in ifaces:
            self._lan_combo.setCurrentText(lan)
        self._server_ip_input.setText(cfg.get("server_ip", ""))
        self._client_net_input.setText(cfg.get("client_network", ""))
        self._rules_path_input.setText(cfg.get("rules_file", ""))
        self._log_path_input.setText(cfg.get("log_file", ""))
        self._refresh_spin.setValue(cfg.get("domain_refresh_interval", 3600))
        action = cfg.get("default_action", "DROP")
        idx = self._action_combo.findText(action)
        if idx >= 0:
            self._action_combo.setCurrentIndex(idx)

    def _save_network(self):
        server_ok, server_msg = validators.validate_ipv4(self._server_ip_input.text()) \
            if self._server_ip_input.text().strip() else (True, "")
        client_ok, client_msg = (True, "")
        if self._client_net_input.text().strip():
            client_ok, client_msg = validators.validate_cidr(self._client_net_input.text())
        if not server_ok:
            self._net_error.setText(f"IP servidor: {server_msg}")
            return
        if not client_ok:
            self._net_error.setText(f"Red cliente: {client_msg}")
            return
        self._net_error.setText("")
        self._config.setdefault("interfaces", {})
        self._config["interfaces"]["wan"] = self._wan_combo.currentText()
        self._config["interfaces"]["lan"] = self._lan_combo.currentText()
        self._config["server_ip"] = self._server_ip_input.text().strip()
        self._config["client_network"] = self._client_net_input.text().strip()
        self.config_changed.emit(self._config)

    def _save_paths(self):
        rules = self._rules_path_input.text().strip()
        log = self._log_path_input.text().strip()
        if rules:
            self._config["rules_file"] = rules
        if log:
            self._config["log_file"] = log
        self.config_changed.emit(self._config)

    def _save_behavior(self):
        self._config["domain_refresh_interval"] = self._refresh_spin.value()
        self._config["default_action"] = self._action_combo.currentText()
        self.config_changed.emit(self._config)

    def _auto_detect(self):
        ip, iface = network_service.get_own_ip_and_interface()
        self._server_ip_input.setText(ip)
        ifaces = network_service.get_available_interfaces()
        if iface in ifaces:
            self._lan_combo.setCurrentText(iface)

    def update_config(self, config: dict):
        self._config = config
        self._load_config()
