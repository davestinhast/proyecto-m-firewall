"""
Pantalla 8 — Configuración general
"""

import subprocess
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QLineEdit, QComboBox,
    QSpinBox, QFormLayout, QFileDialog,
)
from PySide6.QtCore import Qt, Signal, QThread
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
        layout.addWidget(self._build_routing_diag_card())
        layout.addWidget(self._build_paths_card())
        layout.addWidget(self._build_behavior_card())

        # Un solo botón Guardar para toda la página
        self._save_error_lbl = QLabel("")
        self._save_error_lbl.setStyleSheet("color: #D95C5C; font-size: 12px;")
        layout.addWidget(self._save_error_lbl)

        save_row = QHBoxLayout()
        btn_save_all = QPushButton("Guardar configuración")
        btn_save_all.setObjectName("btn_primary")
        btn_save_all.setMinimumHeight(38)
        btn_save_all.setMinimumWidth(200)
        btn_save_all.clicked.connect(self._save_all)
        save_row.addStretch()
        save_row.addWidget(btn_save_all)
        layout.addLayout(save_row)

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
        btn_detect = QPushButton("Detectar automáticamente")
        btn_detect.setObjectName("btn_secondary")
        btn_detect.clicked.connect(self._auto_detect)
        btn_row.addWidget(btn_detect)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return frame

    def _build_routing_diag_card(self) -> QFrame:
        outer = QFrame()
        outer.setObjectName("card")
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(20, 14, 20, 14)
        outer_layout.setSpacing(0)

        # Toggle header — collapsed by default
        self._diag_toggle_btn = QPushButton("▶  Diagnóstico de enrutamiento  (configuración avanzada)")
        self._diag_toggle_btn.setObjectName("btn_link")
        self._diag_toggle_btn.clicked.connect(self._toggle_diag)
        outer_layout.addWidget(self._diag_toggle_btn)

        # Collapsible content
        self._diag_content = QWidget()
        content_layout = QVBoxLayout(self._diag_content)
        content_layout.setContentsMargins(0, 14, 0, 4)
        content_layout.setSpacing(12)

        desc_row = QHBoxLayout()
        desc = QLabel(
            "Para que el bloqueo funcione en los clientes, éstos deben tener la IP de Kali "
            "como gateway (puerta de enlace). Si no, su tráfico nunca pasa por Kali."
        )
        desc.setObjectName("label_secondary")
        desc.setWordWrap(True)
        desc_row.addWidget(desc, stretch=1)
        btn_diag = QPushButton("Ejecutar diagnóstico")
        btn_diag.setObjectName("btn_secondary")
        btn_diag.clicked.connect(self._run_diag)
        desc_row.addWidget(btn_diag)
        content_layout.addLayout(desc_row)

        self._diag_labels: dict = {}
        checks = [
            ("ip_forward", "IP Forward (net.ipv4.ip_forward)"),
            ("masquerade", "NAT MASQUERADE en iptables"),
            ("wan_set",    "Interfaz WAN configurada"),
            ("lan_set",    "Interfaz LAN configurada"),
            ("server_ip",  "IP del servidor configurada"),
        ]
        for key, text in checks:
            row = QHBoxLayout()
            lbl_key = QLabel(text)
            lbl_key.setObjectName("label_secondary")
            lbl_key.setMinimumWidth(280)
            lbl_val = QLabel("—")
            lbl_val.setObjectName("label_secondary")
            row.addWidget(lbl_key)
            row.addWidget(lbl_val)
            row.addStretch()
            content_layout.addLayout(row)
            self._diag_labels[key] = lbl_val

        instruct_frame = QFrame()
        instruct_frame.setObjectName("card_step_pending")
        instruct_layout = QVBoxLayout(instruct_frame)
        instruct_layout.setContentsMargins(16, 12, 16, 12)
        instruct_layout.setSpacing(6)
        inst_title = QLabel("Cómo configurar el gateway en los clientes")
        inst_title.setObjectName("label_subtitle")
        instruct_layout.addWidget(inst_title)
        self._instruct_label = QLabel("Ejecuta el diagnóstico para ver las instrucciones.")
        self._instruct_label.setObjectName("label_secondary")
        self._instruct_label.setWordWrap(True)
        instruct_layout.addWidget(self._instruct_label)
        content_layout.addWidget(instruct_frame)

        self._diag_content.setVisible(False)
        outer_layout.addWidget(self._diag_content)
        return outer

    def _toggle_diag(self):
        visible = self._diag_content.isVisible()
        self._diag_content.setVisible(not visible)
        arrow = "▼" if not visible else "▶"
        self._diag_toggle_btn.setText(
            f"{arrow}  Diagnóstico de enrutamiento  (configuración avanzada)"
        )

    def _run_diag(self):
        # Auto-expand if collapsed
        if not self._diag_content.isVisible():
            self._diag_content.setVisible(True)
            self._diag_toggle_btn.setText("▼  Diagnóstico de enrutamiento  (configuración avanzada)")

        from app.core.platform_detector import is_linux, has_ip_forward

        # ip_forward
        ip_fwd = has_ip_forward() if is_linux() else False
        self._set_diag("ip_forward", ip_fwd, "Activo" if ip_fwd else "INACTIVO — ejecuta 'Aplicar reglas' para activarlo")

        # MASQUERADE en iptables
        masq = False
        if is_linux():
            try:
                result = subprocess.run(
                    ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n"],
                    capture_output=True, text=True, timeout=5
                )
                masq = "MASQUERADE" in result.stdout
            except Exception:
                masq = False
        self._set_diag("masquerade", masq,
                       "Configurado" if masq else "FALTA — aplica las reglas primero")

        # Interfaces
        wan = self._config.get("interfaces", {}).get("wan", "")
        lan = self._config.get("interfaces", {}).get("lan", "")
        self._set_diag("wan_set", bool(wan), wan if wan else "No configurada")
        self._set_diag("lan_set", bool(lan), lan if lan else "No configurada")

        # IP servidor
        server_ip = self._config.get("server_ip", "")
        self._set_diag("server_ip", bool(server_ip),
                       server_ip if server_ip else "No configurada")

        # Instrucciones para clientes
        if server_ip:
            net = self._config.get("client_network", "")
            instructions = (
                f"En cada PC cliente, configura la puerta de enlace (gateway) a:  {server_ip}\n\n"
                f"Windows:  Panel de control → Centro de redes → Adaptador → Propiedades → "
                f"IPv4 → Gateway predeterminado: {server_ip}\n\n"
                f"Linux:  sudo ip route add default via {server_ip}\n\n"
                f"Android/iOS:  WiFi → editar red → Gateway: {server_ip}\n\n"
                f"Verificar en el cliente (cmd/terminal):  route print  o  ip route"
            )
        else:
            instructions = (
                "Primero configura la IP del servidor en la sección 'Red' de arriba, "
                "luego vuelve a ejecutar el diagnóstico."
            )
        self._instruct_label.setText(instructions)

    def _set_diag(self, key: str, ok: bool, text: str):
        lbl = self._diag_labels.get(key)
        if lbl:
            color = "#22c55e" if ok else "#ef4444"
            prefix = "✓" if ok else "✗"
            lbl.setStyleSheet(f"color: {color}; font-weight: 600; background: transparent;")
            lbl.setText(f"{prefix}  {text}")

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

    def _save_all(self):
        """Guarda todas las secciones en un solo paso."""
        # Validar red primero
        if self._server_ip_input.text().strip():
            ok, msg = validators.validate_ipv4(self._server_ip_input.text())
            if not ok:
                self._save_error_lbl.setText(f"IP servidor: {msg}")
                return
        if self._client_net_input.text().strip():
            ok, msg = validators.validate_cidr(self._client_net_input.text())
            if not ok:
                self._save_error_lbl.setText(f"Red cliente: {msg}")
                return
        self._save_error_lbl.setText("")
        self._save_network()
        self._save_paths()
        self._save_behavior()

    def _auto_detect(self):
        ip, iface = network_service.get_own_ip_and_interface()
        self._server_ip_input.setText(ip)
        ifaces = network_service.get_available_interfaces()
        if iface in ifaces:
            self._lan_combo.setCurrentText(iface)

    def update_config(self, config: dict):
        self._config = config
        self._load_config()
