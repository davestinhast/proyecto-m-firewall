"""
Pantalla 3 — Cliente / Servidor (bloqueo unidireccional)
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QLineEdit, QComboBox,
    QCheckBox, QFormLayout,
)
from PySide6.QtCore import Qt, Signal
from app.ui.widgets.toggle_switch import ToggleSwitch
from app.core import validators
from app.services import network_service


class CliSrvPage(QWidget):
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

        title = QLabel("Control cliente / servidor")
        title.setObjectName("label_title")
        layout.addWidget(title)

        # Diagrama visual
        layout.addWidget(self._build_diagram())

        # Configuración
        layout.addWidget(self._build_config_card())

        layout.addStretch()
        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def _build_diagram(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card_accent_blue")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(24, 18, 24, 18)
        layout.setSpacing(10)

        subtitle = QLabel("Diagrama de tráfico")
        subtitle.setObjectName("label_subtitle")
        layout.addWidget(subtitle)

        row = QHBoxLayout()
        row.setSpacing(0)

        def box(text, color):
            lbl = QLabel(text)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(
                f"background-color: #1B1F27; color: {color}; "
                "border: 1px solid #2A303B; border-radius: 6px; "
                "padding: 12px 20px; font-weight: 600; font-size: 14px;"
            )
            return lbl

        self._srv_label = box("SERVIDOR\n192.168.50.1", "#4F7DF3")
        self._allow_arrow = QLabel("  ──────────────▶  ")
        self._allow_arrow.setObjectName("label_secondary")
        self._allow_arrow.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._cli_label = box("CLIENTE\n192.168.50.10", "#3CB371")

        self._block_row = QHBoxLayout()
        self._block_row.setSpacing(0)
        block_arrow = QLabel("  ━━━━━━━━━━ ✕ ━━▶  ")
        block_arrow.setAlignment(Qt.AlignmentFlag.AlignCenter)
        block_arrow.setStyleSheet("color: #D95C5C; font-weight: 700;")

        allow_text = QLabel("Servidor → Cliente: PERMITIDO")
        allow_text.setObjectName("status_active")
        block_text = QLabel("Cliente → Servidor (NEW): BLOQUEADO")
        block_text.setObjectName("status_inactive")

        row.addWidget(self._srv_label)
        row.addWidget(self._allow_arrow)
        row.addWidget(self._cli_label)
        layout.addLayout(row)

        info_col = QVBoxLayout()
        info_col.addWidget(allow_text)
        info_col.addWidget(block_text)
        layout.addLayout(info_col)
        return frame

    def _build_config_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(14)

        top_row = QHBoxLayout()
        subtitle = QLabel("Configuración")
        subtitle.setObjectName("label_subtitle")
        top_row.addWidget(subtitle)
        top_row.addStretch()
        self._enabled_toggle = ToggleSwitch()
        self._enabled_toggle.toggled.connect(self._on_save)
        top_row.addWidget(QLabel("Activar regla:"))
        top_row.addWidget(self._enabled_toggle)
        layout.addLayout(top_row)

        form = QFormLayout()
        form.setSpacing(10)

        self._srv_ip_input = QLineEdit()
        self._srv_ip_input.setPlaceholderText("ej: 192.168.50.1")
        self._cli_ip_input = QLineEdit()
        self._cli_ip_input.setPlaceholderText("ej: 192.168.50.10")

        self._iface_combo = QComboBox()
        self._iface_combo.addItem("(cualquier interfaz)")
        self._iface_combo.addItems(network_service.get_available_interfaces())

        self._action_combo = QComboBox()
        self._action_combo.addItems(["DROP", "REJECT"])

        self._proto_tcp = QCheckBox("TCP")
        self._proto_udp = QCheckBox("UDP")
        self._proto_icmp = QCheckBox("ICMP")
        self._proto_tcp.setChecked(True)

        proto_row = QHBoxLayout()
        proto_row.addWidget(self._proto_tcp)
        proto_row.addWidget(self._proto_udp)
        proto_row.addWidget(self._proto_icmp)
        proto_row.addStretch()

        form.addRow("IP del servidor:", self._srv_ip_input)
        form.addRow("IP del cliente:", self._cli_ip_input)
        form.addRow("Interfaz LAN:", self._iface_combo)
        form.addRow("Protocolos:", proto_row)
        form.addRow("Acción:", self._action_combo)
        layout.addLayout(form)

        self._error_label = QLabel("")
        self._error_label.setStyleSheet("color: #D95C5C; font-size: 12px;")
        layout.addWidget(self._error_label)

        btn_row = QHBoxLayout()
        btn_save = QPushButton("Guardar configuración")
        btn_save.setObjectName("btn_primary")
        btn_save.clicked.connect(self._on_save)
        btn_row.addWidget(btn_save)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return frame

    def _load_config(self):
        clisrv = self._config.get("clisrv", {})
        self._enabled_toggle.setChecked(clisrv.get("enabled", False))
        self._srv_ip_input.setText(clisrv.get("server_ip", ""))
        self._cli_ip_input.setText(clisrv.get("client_ip", ""))
        protos = clisrv.get("protocols", ["tcp"])
        self._proto_tcp.setChecked("tcp" in protos)
        self._proto_udp.setChecked("udp" in protos)
        self._proto_icmp.setChecked("icmp" in protos)
        action = clisrv.get("action", "DROP")
        idx = self._action_combo.findText(action)
        if idx >= 0:
            self._action_combo.setCurrentIndex(idx)

    def _on_save(self):
        srv_ok, srv_msg = validators.validate_ipv4(self._srv_ip_input.text())
        cli_ok, cli_msg = validators.validate_ipv4(self._cli_ip_input.text())

        if not srv_ok:
            self._error_label.setText(f"IP servidor: {srv_msg}")
            return
        if not cli_ok:
            self._error_label.setText(f"IP cliente: {cli_msg}")
            return

        self._error_label.setText("")
        protocols = []
        if self._proto_tcp.isChecked(): protocols.append("tcp")
        if self._proto_udp.isChecked(): protocols.append("udp")
        if self._proto_icmp.isChecked(): protocols.append("icmp")
        if not protocols:
            protocols = ["tcp"]

        iface = self._iface_combo.currentText()
        self._config["clisrv"] = {
            "enabled": self._enabled_toggle.isChecked(),
            "server_ip": validators.normalize_ip(self._srv_ip_input.text()),
            "client_ip": validators.normalize_ip(self._cli_ip_input.text()),
            "interface": "" if "(cualquier" in iface else iface,
            "protocols": protocols,
            "action": self._action_combo.currentText(),
        }
        self.config_changed.emit(self._config)

    def update_config(self, config: dict):
        self._config = config
        self._load_config()
