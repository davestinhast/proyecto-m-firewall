"""
Pantalla 5 — Límite de conexiones simultáneas (connlimit)
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QComboBox, QSpinBox, QDialog,
    QDialogButtonBox, QFormLayout,
)
from PySide6.QtCore import Qt, Signal
from app.ui.widgets.toggle_switch import ToggleSwitch
from app.constants import DEFAULT_CONN_PROFILES
import copy


class AddProfileDialog(QDialog):
    def __init__(self, profile: dict = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Perfil de conexiones")
        self.setMinimumWidth(380)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)

        title = QLabel("Configurar límite de conexiones")
        title.setObjectName("label_subtitle")
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(8)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("ej: SSH restringido")

        self.proto_combo = QComboBox()
        self.proto_combo.addItems(["tcp", "udp"])

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(22)

        self.max_spin = QSpinBox()
        self.max_spin.setRange(1, 1000)
        self.max_spin.setValue(3)

        self.action_combo = QComboBox()
        self.action_combo.addItems(["REJECT", "DROP"])

        if profile:
            self.name_input.setText(profile.get("name", ""))
            idx = self.proto_combo.findText(profile.get("proto", "tcp"))
            if idx >= 0: self.proto_combo.setCurrentIndex(idx)
            self.port_spin.setValue(profile.get("port", 22))
            self.max_spin.setValue(profile.get("max", 3))
            idx2 = self.action_combo.findText(profile.get("action", "REJECT"))
            if idx2 >= 0: self.action_combo.setCurrentIndex(idx2)

        form.addRow("Nombre:", self.name_input)
        form.addRow("Protocolo:", self.proto_combo)
        form.addRow("Puerto:", self.port_spin)
        form.addRow("Máximo conexiones:", self.max_spin)
        form.addRow("Acción al exceder:", self.action_combo)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_profile(self) -> dict:
        return {
            "name": self.name_input.text().strip() or f"Puerto {self.port_spin.value()}",
            "proto": self.proto_combo.currentText(),
            "port": self.port_spin.value(),
            "max": self.max_spin.value(),
            "action": self.action_combo.currentText(),
            "enabled": True,
        }


class ConnectionsPage(QWidget):
    config_changed = Signal(dict)

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        if not self._config.get("conn_profiles"):
            self._config["conn_profiles"] = copy.deepcopy(DEFAULT_CONN_PROFILES)
        self._setup_ui()
        self._refresh_table()

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

        title = QLabel("Límite de conexiones simultáneas")
        title.setObjectName("label_title")
        layout.addWidget(title)

        desc = QLabel(
            "Usa el módulo connlimit de iptables para limitar cuántas conexiones simultáneas "
            "puede abrir una misma IP hacia un puerto específico."
        )
        desc.setObjectName("label_secondary")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        layout.addWidget(self._build_profiles_card())

        # Info técnica
        info_frame = QFrame()
        info_frame.setObjectName("card")
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(20, 14, 20, 14)
        info_layout.setSpacing(6)
        info_layout.addWidget(QLabel("Regla generada por perfil:").setObjectName("label_subtitle") or
                              QLabel("Regla generada por perfil:"))

        example_lbl = QLabel(
            "iptables -A PM_CONNLIMIT -p tcp --dport 22 "
            "-m connlimit --connlimit-above 3 --connlimit-mask 32 "
            "-j REJECT --reject-with tcp-reset"
        )
        example_lbl.setObjectName("label_mono")
        example_lbl.setWordWrap(True)
        info_layout.addWidget(example_lbl)
        layout.addWidget(info_frame)

        layout.addStretch()
        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def _build_profiles_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        top_row = QHBoxLayout()
        subtitle = QLabel("Perfiles configurados")
        subtitle.setObjectName("label_subtitle")
        top_row.addWidget(subtitle)
        top_row.addStretch()

        btn_add = QPushButton("+ Nuevo perfil")
        btn_add.setObjectName("btn_primary")
        btn_add.clicked.connect(self._add_profile)
        top_row.addWidget(btn_add)
        layout.addLayout(top_row)

        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(["Nombre", "Proto", "Puerto", "Máx. conex.", "Acción", "Activo"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setMaximumHeight(320)
        layout.addWidget(self._table)

        return frame

    def _refresh_table(self):
        profiles = self._config.get("conn_profiles", [])
        self._table.setRowCount(len(profiles))
        for row, p in enumerate(profiles):
            self._table.setItem(row, 0, QTableWidgetItem(p.get("name", "")))
            self._table.setItem(row, 1, QTableWidgetItem(p.get("proto", "tcp")))
            self._table.setItem(row, 2, QTableWidgetItem(str(p.get("port", ""))))
            self._table.setItem(row, 3, QTableWidgetItem(str(p.get("max", "")) + " conexiones"))
            self._table.setItem(row, 4, QTableWidgetItem(p.get("action", "REJECT")))

            toggle = ToggleSwitch()
            toggle.setChecked(p.get("enabled", True))
            toggle.toggled.connect(lambda checked, r=row: self._toggle_profile(r, checked))
            cell_widget = QWidget()
            cell_layout = QHBoxLayout(cell_widget)
            cell_layout.setContentsMargins(8, 4, 8, 4)
            cell_layout.addWidget(toggle)
            self._table.setCellWidget(row, 5, cell_widget)

    def _add_profile(self):
        dialog = AddProfileDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._config["conn_profiles"].append(dialog.get_profile())
            self._refresh_table()
            self.config_changed.emit(self._config)

    def _toggle_profile(self, row: int, enabled: bool):
        profiles = self._config.get("conn_profiles", [])
        if 0 <= row < len(profiles):
            profiles[row]["enabled"] = enabled
            self.config_changed.emit(self._config)

    def update_config(self, config: dict):
        self._config = config
        if not self._config.get("conn_profiles"):
            self._config["conn_profiles"] = copy.deepcopy(DEFAULT_CONN_PROFILES)
        self._refresh_table()
