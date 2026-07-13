"""
Pantalla 4 — Bloqueo por dirección MAC
Incluye escáner de red para detectar dispositivos automáticamente.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QComboBox, QDialog, QDialogButtonBox,
    QFormLayout, QMessageBox,
)
from PySide6.QtCore import Qt, Signal
from app.core import validators
from app.services import network_service
from app.workers.apply_worker import ScanNetworkWorker
from app.constants import COLOR_GREEN, COLOR_RED


class AddMacDialog(QDialog):
    def __init__(self, mac: str = "", ip: str = "", hostname: str = "", interfaces: list = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Agregar equipo a bloquear")
        self.setMinimumWidth(420)
        self.setObjectName("card")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        title = QLabel("Nuevo equipo bloqueado")
        title.setObjectName("label_subtitle")
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(10)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("ej: PC Windows del cliente")
        self.mac_input = QLineEdit(mac)
        self.mac_input.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        self.iface_combo = QComboBox()
        ifaces = interfaces or network_service.get_available_interfaces()
        self.iface_combo.addItem("(cualquier interfaz)")
        self.iface_combo.addItems(ifaces)
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("ej: equipo no autorizado")

        if ip:
            self.name_input.setText(hostname or ip)

        form.addRow("Nombre del equipo:", self.name_input)
        form.addRow("Dirección MAC:", self.mac_input)
        form.addRow("Interfaz de entrada:", self.iface_combo)
        form.addRow("Motivo:", self.reason_input)
        layout.addLayout(form)

        self._error_label = QLabel("")
        self._error_label.setStyleSheet("color: #ff3333; font-size: 12px; background: transparent;")
        layout.addWidget(self._error_label)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _validate_and_accept(self):
        ok, msg = validators.validate_mac(self.mac_input.text())
        if not ok:
            self._error_label.setText(msg)
            return
        if not self.name_input.text().strip():
            self._error_label.setText("El nombre es requerido.")
            return
        self.accept()

    def get_rule(self) -> dict:
        iface = self.iface_combo.currentText()
        return {
            "name": self.name_input.text().strip(),
            "mac": validators.normalize_mac(self.mac_input.text()),
            "interface": "" if "(cualquier" in iface else iface,
            "reason": self.reason_input.text().strip(),
            "enabled": True,
        }


class MacPage(QWidget):
    config_changed = Signal(dict)

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._scan_worker = None
        self._scanned_devices: list[dict] = []
        self._setup_ui()
        self._refresh_rules_table()

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

        # Título
        title = QLabel("Bloqueo por dirección MAC")
        title.setObjectName("label_title")
        layout.addWidget(title)

        layout.addWidget(self._build_scanner_section())
        layout.addWidget(self._build_rules_section())
        layout.addStretch()

        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def _build_scanner_section(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        subtitle = QLabel("Dispositivos en la red local")
        subtitle.setObjectName("label_subtitle")
        layout.addWidget(subtitle)

        desc = QLabel(
            "Escanea la red para detectar equipos conectados. "
            "Selecciona un equipo y agréguelo directamente a la lista de bloqueo."
        )
        desc.setObjectName("label_secondary")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Barra de acciones
        btn_row = QHBoxLayout()
        self._scan_btn = QPushButton("Escanear red ahora")
        self._scan_btn.setObjectName("btn_primary")
        self._scan_btn.clicked.connect(self._start_scan)
        btn_row.addWidget(self._scan_btn)

        self._scan_status = QLabel("")
        self._scan_status.setObjectName("label_secondary")
        btn_row.addWidget(self._scan_status)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Tabla de dispositivos detectados
        self._scan_table = QTableWidget(0, 5)
        self._scan_table.setHorizontalHeaderLabels(["IP", "MAC", "Hostname", "Fabricante", "Estado"])
        self._scan_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._scan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._scan_table.setAlternatingRowColors(True)
        self._scan_table.setMaximumHeight(220)
        self._scan_table.verticalHeader().setVisible(False)
        self._scan_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._scan_table)

        # Botón agregar seleccionado
        btn_add_row = QHBoxLayout()
        btn_add_selected = QPushButton("Bloquear equipo seleccionado")
        btn_add_selected.setObjectName("btn_danger")
        btn_add_selected.clicked.connect(self._add_selected_device)
        btn_add_row.addWidget(btn_add_selected)
        btn_add_row.addStretch()
        layout.addLayout(btn_add_row)

        return frame

    def _build_rules_section(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        top_row = QHBoxLayout()
        subtitle = QLabel("Equipos bloqueados")
        subtitle.setObjectName("label_subtitle")
        top_row.addWidget(subtitle)
        top_row.addStretch()

        btn_add_manual = QPushButton("+ Agregar manualmente")
        btn_add_manual.setObjectName("btn_secondary")
        btn_add_manual.clicked.connect(self._add_manual)
        top_row.addWidget(btn_add_manual)
        layout.addLayout(top_row)

        self._rules_table = QTableWidget(0, 6)
        self._rules_table.setHorizontalHeaderLabels(["Equipo", "MAC", "Interfaz", "Motivo", "Estado", "Acciones"])
        self._rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._rules_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._rules_table.setAlternatingRowColors(True)
        self._rules_table.verticalHeader().setVisible(False)
        self._rules_table.setMaximumHeight(280)
        layout.addWidget(self._rules_table)

        return frame

    def _start_scan(self):
        own_ip, _ = network_service.get_own_ip_and_interface()
        subnet = network_service.get_subnet(own_ip)
        self._scan_btn.setEnabled(False)
        self._scan_status.setText(f"Escaneando {subnet}...")
        self._scan_worker = ScanNetworkWorker(subnet)
        self._scan_worker.finished.connect(self._on_scan_done)
        self._scan_worker.start()

    def _on_scan_done(self, devices: list[dict]):
        self._scanned_devices = devices
        self._scan_table.setRowCount(len(devices))
        for row, dev in enumerate(devices):
            self._scan_table.setItem(row, 0, QTableWidgetItem(dev.get("ip", "")))
            self._scan_table.setItem(row, 1, QTableWidgetItem(dev.get("mac", "")))
            self._scan_table.setItem(row, 2, QTableWidgetItem(dev.get("hostname", "")))
            self._scan_table.setItem(row, 3, QTableWidgetItem(dev.get("vendor", "")))
            status_item = QTableWidgetItem(dev.get("status", "activo"))
            status_item.setForeground(Qt.GlobalColor.green)
            self._scan_table.setItem(row, 4, status_item)
        self._scan_status.setText(f"{len(devices)} dispositivos encontrados.")
        self._scan_btn.setEnabled(True)

    def _add_selected_device(self):
        row = self._scan_table.currentRow()
        if row < 0 or row >= len(self._scanned_devices):
            QMessageBox.warning(self, "Selección", "Selecciona un dispositivo de la tabla primero.")
            return
        dev = self._scanned_devices[row]
        self._open_add_dialog(
            mac=dev.get("mac", ""),
            ip=dev.get("ip", ""),
            hostname=dev.get("hostname", ""),
        )

    def _add_manual(self):
        self._open_add_dialog()

    def _open_add_dialog(self, mac: str = "", ip: str = "", hostname: str = ""):
        ifaces = network_service.get_available_interfaces()
        dialog = AddMacDialog(mac=mac, ip=ip, hostname=hostname, interfaces=ifaces, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            rule = dialog.get_rule()
            if "mac_rules" not in self._config:
                self._config["mac_rules"] = []
            self._config["mac_rules"].append(rule)
            self._refresh_rules_table()
            self.config_changed.emit(self._config)

    def _refresh_rules_table(self):
        rules = self._config.get("mac_rules", [])
        self._rules_table.setRowCount(len(rules))
        for row, rule in enumerate(rules):
            self._rules_table.setItem(row, 0, QTableWidgetItem(rule.get("name", "")))
            self._rules_table.setItem(row, 1, QTableWidgetItem(rule.get("mac", "")))
            self._rules_table.setItem(row, 2, QTableWidgetItem(rule.get("interface", "(todas)")))
            self._rules_table.setItem(row, 3, QTableWidgetItem(rule.get("reason", "")))

            status_text = "Activo" if rule.get("enabled", True) else "Inactivo"
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(Qt.GlobalColor.green if rule.get("enabled") else Qt.GlobalColor.red)
            self._rules_table.setItem(row, 4, status_item)

            action_btn = QPushButton("Eliminar")
            action_btn.setObjectName("btn_small")
            action_btn.clicked.connect(lambda _, r=row: self._delete_rule(r))
            self._rules_table.setCellWidget(row, 5, action_btn)

    def _delete_rule(self, row: int):
        rules = self._config.get("mac_rules", [])
        if 0 <= row < len(rules):
            rules.pop(row)
            self._refresh_rules_table()
            self.config_changed.emit(self._config)

    def showEvent(self, event):
        """Auto-escanear al abrir la página si aún no hay dispositivos."""
        super().showEvent(event)
        if not self._scanned_devices and not (self._scan_worker and self._scan_worker.isRunning()):
            self._start_scan()

    def update_config(self, config: dict):
        self._config = config
        self._refresh_rules_table()
