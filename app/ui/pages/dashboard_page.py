"""
Pantalla 1 — Inicio / Dashboard
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QGridLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QSizePolicy,
)
from PySide6.QtCore import Qt, QTimer
from app.ui.widgets.stat_card import StatCard
from app.core.platform_detector import get_system_info, get_mode
from app.services import logging_service, network_service
from app.constants import APP_AUTHORS


class DashboardPage(QWidget):
    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._refresh()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_log_preview)
        self._timer.start(5000)

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(20)

        # Título
        title = QLabel("Inicio")
        title.setObjectName("label_title")
        layout.addWidget(title)

        # Tarjetas de estadísticas
        self._stats_grid = QGridLayout()
        self._stats_grid.setSpacing(12)

        self._card_status    = StatCard("Estado del firewall",      "ACTIVO",  "green")
        self._card_rules     = StatCard("Reglas cargadas",          "0",       "blue")
        self._card_macs      = StatCard("MACs bloqueadas",          "0",       "red")
        self._card_sites     = StatCard("Sitios restringidos",      "0",       "blue")
        self._card_rejected  = StatCard("Paquetes rechazados hoy",  "0",       "red")
        self._card_last_app  = StatCard("Última aplicación",        "—",       "blue")

        cards = [
            self._card_status, self._card_rules,
            self._card_macs, self._card_sites,
            self._card_rejected, self._card_last_app,
        ]
        for i, card in enumerate(cards):
            self._stats_grid.addWidget(card, i // 3, i % 3)

        layout.addLayout(self._stats_grid)

        # Info del sistema
        layout.addWidget(self._build_system_info())

        # Últimos paquetes rechazados
        layout.addWidget(self._build_log_section())

        # Integrantes
        layout.addWidget(self._build_authors())

        layout.addStretch()

        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def _build_system_info(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        subtitle = QLabel("Información del sistema")
        subtitle.setObjectName("label_subtitle")
        layout.addWidget(subtitle)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        info = get_system_info()
        cfg = self._config
        mode = get_mode()

        rows = [
            ("Modo",           "ADMINISTRACIÓN" if mode == "admin" else "DEMOSTRACIÓN"),
            ("Backend",        "iptables ✓" if info["has_iptables"] else "No detectado"),
            ("ipset",          "✓" if info["has_ipset"] else "No detectado"),
            ("Privilegios",    "root ✓" if info["is_root"] else "usuario normal"),
            ("Interfaz WAN",   cfg.get("interfaces", {}).get("wan", "—")),
            ("Interfaz LAN",   cfg.get("interfaces", {}).get("lan", "—")),
            ("IP servidor",    cfg.get("server_ip", "—")),
            ("Red cliente",    cfg.get("client_network", "—")),
            ("Sistema",        f"{info['os']} {info['release']}"),
            ("Python",         info["python"]),
        ]

        for i, (key, val) in enumerate(rows):
            col = (i % 2) * 2
            row = i // 2
            key_lbl = QLabel(key + ":")
            key_lbl.setObjectName("label_secondary")
            val_lbl = QLabel(str(val))
            val_lbl.setObjectName("label_mono")
            grid.addWidget(key_lbl, row, col)
            grid.addWidget(val_lbl, row, col + 1)

        layout.addLayout(grid)
        return frame

    def _build_log_section(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        subtitle = QLabel("Últimos paquetes rechazados")
        subtitle.setObjectName("label_subtitle")
        layout.addWidget(subtitle)

        self._log_table = QTableWidget(0, 5)
        self._log_table.setHorizontalHeaderLabels(["Hora", "Origen", "Destino", "Proto", "Motivo"])
        self._log_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._log_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._log_table.setAlternatingRowColors(True)
        self._log_table.setMaximumHeight(240)
        self._log_table.verticalHeader().setVisible(False)
        self._log_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._log_table)
        return frame

    def _build_authors(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(6)

        subtitle = QLabel("Integrantes del proyecto")
        subtitle.setObjectName("label_subtitle")
        layout.addWidget(subtitle)

        for author in APP_AUTHORS:
            lbl = QLabel(f"• {author}")
            lbl.setObjectName("label_secondary")
            layout.addWidget(lbl)

        return frame

    def _refresh(self):
        cfg = self._config
        mac_count = len([r for r in cfg.get("mac_rules", []) if r.get("enabled")])
        site_count = len([v for v in cfg.get("blocked_domains", {}).values() if v.get("enabled")])

        self._card_macs.set_value(str(mac_count))
        self._card_sites.set_value(str(site_count))
        self._card_rejected.set_value(str(logging_service.count_rejected_today()))
        self._refresh_log_preview()

    def _refresh_log_preview(self):
        entries = logging_service.read_log_tail(5)
        self._log_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            self._log_table.setItem(row, 0, QTableWidgetItem(entry.get("time", "")))
            self._log_table.setItem(row, 1, QTableWidgetItem(entry.get("src", "")))
            self._log_table.setItem(row, 2, QTableWidgetItem(entry.get("dst", "")))
            self._log_table.setItem(row, 3, QTableWidgetItem(entry.get("proto", "")))
            self._log_table.setItem(row, 4, QTableWidgetItem(entry.get("reason", "")))

    def update_config(self, config: dict):
        self._config = config
        self._refresh()
