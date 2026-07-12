"""
Pantalla 1 — Inicio / Dashboard
Estado del firewall + acciones principales.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QGridLayout,
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QCursor
from app.core.platform_detector import get_system_info, get_mode
from app.services import logging_service, network_service
from app.constants import APP_AUTHORS, APP_VERSION


class DashboardPage(QWidget):
    navigate_requested = Signal(str)
    apply_requested    = Signal()

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._refresh()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(6000)

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        container = QWidget()
        self._layout = QVBoxLayout(container)
        self._layout.setContentsMargins(32, 28, 32, 28)
        self._layout.setSpacing(16)

        self._layout.addWidget(self._build_hero_card())
        self._layout.addWidget(self._build_status_grid())
        self._layout.addWidget(self._build_stats_row())
        self._layout.addWidget(self._build_log_preview())
        self._layout.addSpacing(8)
        self._layout.addWidget(self._build_footer_info())
        self._layout.addStretch()

        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    # ─── HERO ────────────────────────────────────────────────────────────────
    def _build_hero_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(0)

        left = QWidget()
        left.setObjectName("card_inner")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        title = QLabel("M-FIREWALL")
        title.setObjectName("label_title")
        subtitle = QLabel("Administrador de reglas iptables · Kali Linux")
        subtitle.setObjectName("label_secondary")

        self._fw_state_label = QLabel("INACTIVO — sin reglas configuradas")
        self._fw_state_label.setStyleSheet(
            "color: #ef4444; font-size: 20px; font-weight: 700; background: transparent;"
        )

        left_layout.addWidget(title)
        left_layout.addWidget(subtitle)
        left_layout.addSpacing(12)
        left_layout.addWidget(self._fw_state_label)
        layout.addWidget(left, stretch=1)

        right = QWidget()
        right.setObjectName("card_inner")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        self._btn_apply_hero = QPushButton("Aplicar reglas")
        self._btn_apply_hero.setObjectName("btn_primary")
        self._btn_apply_hero.setMinimumHeight(44)
        self._btn_apply_hero.setMinimumWidth(160)
        self._btn_apply_hero.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._btn_apply_hero.clicked.connect(self.apply_requested.emit)

        if get_mode() == "demo":
            self._btn_apply_hero.setEnabled(False)
            self._btn_apply_hero.setToolTip("Solo disponible en Kali Linux con iptables")

        right_layout.addWidget(self._btn_apply_hero)
        layout.addWidget(right)
        return frame

    # ─── STATUS GRID ─────────────────────────────────────────────────────────
    def _build_status_grid(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        outer = QVBoxLayout(frame)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(12)

        hdr_row = QHBoxLayout()
        hdr = QLabel("Estado del sistema")
        hdr.setObjectName("label_subtitle")
        hdr_row.addWidget(hdr)
        hdr_row.addStretch()
        outer.addLayout(hdr_row)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)

        self._grid_widgets: dict = {}

        items = [
            ("mode",       "Modo",           0, 0),
            ("ip_forward", "IP Forward",     0, 1),
            ("iptables",   "iptables",       0, 2),
            ("root",       "Permisos",       1, 0),
            ("iface",      "Interfaz LAN",   1, 1),
            ("server_ip",  "IP servidor",    1, 2),
        ]

        for key, label, row, col in items:
            cell = QFrame()
            cell.setObjectName("card_step_pending")
            cell_layout = QVBoxLayout(cell)
            cell_layout.setContentsMargins(14, 10, 14, 10)
            cell_layout.setSpacing(3)

            key_lbl = QLabel(label)
            key_lbl.setObjectName("label_hint")

            val_lbl = QLabel("—")
            val_lbl.setStyleSheet(
                "color: #E2EAFA; font-weight: 600; font-size: 12px; background: transparent;"
            )

            cell_layout.addWidget(key_lbl)
            cell_layout.addWidget(val_lbl)
            grid.addWidget(cell, row, col)
            self._grid_widgets[key] = val_lbl

        outer.addLayout(grid)

        link_row = QHBoxLayout()
        link_row.setSpacing(8)
        for label, page_id in [("Sitios web", "websites"), ("MACs", "mac"), ("Configuración", "settings")]:
            btn = QPushButton(label)
            btn.setObjectName("btn_small")
            btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            btn.clicked.connect(lambda _, pid=page_id: self.navigate_requested.emit(pid))
            link_row.addWidget(btn)
        link_row.addStretch()
        outer.addLayout(link_row)

        return frame

    # ─── STATS ───────────────────────────────────────────────────────────────
    def _build_stats_row(self) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._stat_widgets: dict = {}

        for label in ("MACs bloqueadas", "Sitios bloqueados", "Paquetes hoy"):
            card = QFrame()
            card.setObjectName("card")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(16, 14, 16, 14)
            card_layout.setSpacing(3)

            val_lbl = QLabel("0")
            val_lbl.setStyleSheet(
                "color: #E2EAFA; font-size: 22px; font-weight: 700; background: transparent;"
            )
            key_lbl = QLabel(label)
            key_lbl.setObjectName("label_hint")

            card_layout.addWidget(val_lbl)
            card_layout.addWidget(key_lbl)
            layout.addWidget(card, stretch=1)
            self._stat_widgets[label] = val_lbl

        return container

    # ─── LOG PREVIEW ─────────────────────────────────────────────────────────
    def _build_log_preview(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(10)

        hdr = QHBoxLayout()
        lbl = QLabel("Últimos paquetes rechazados")
        lbl.setObjectName("label_subtitle")
        hdr.addWidget(lbl)
        hdr.addStretch()
        hint = QLabel("Se actualiza cada 6 segundos")
        hint.setObjectName("label_hint")
        hdr.addWidget(hint)
        layout.addLayout(hdr)

        header_row = QWidget()
        header_row.setObjectName("card_inner")
        hl = QHBoxLayout(header_row)
        hl.setContentsMargins(8, 4, 8, 4)
        hl.setSpacing(0)
        for col_name, stretch in [("Hora", 2), ("Origen", 3), ("Destino", 3), ("Proto", 1), ("Motivo", 3)]:
            h = QLabel(col_name.upper())
            h.setStyleSheet(
                "color: #5C7A95; font-size: 10px; font-weight: 700; "
                "letter-spacing: 1px; background: transparent;"
            )
            hl.addWidget(h, stretch=stretch)
        layout.addWidget(header_row)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        self._log_rows_container = QWidget()
        self._log_rows_container.setObjectName("card_inner")
        self._log_rows_layout = QVBoxLayout(self._log_rows_container)
        self._log_rows_layout.setContentsMargins(0, 0, 0, 0)
        self._log_rows_layout.setSpacing(0)
        layout.addWidget(self._log_rows_container)

        return frame

    def _build_footer_info(self) -> QWidget:
        w = QWidget()
        layout = QHBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        for author in APP_AUTHORS:
            lbl = QLabel(author)
            lbl.setObjectName("label_hint")
            layout.addWidget(lbl)
            layout.addSpacing(20)
        layout.addStretch()
        ver = QLabel(f"M-FIREWALL v{APP_VERSION}")
        ver.setObjectName("label_hint")
        layout.addWidget(ver)
        return w

    # ─── REFRESH ─────────────────────────────────────────────────────────────
    def _refresh(self):
        cfg = self._config
        info = get_system_info()
        mode = get_mode()
        _, iface = network_service.get_own_ip_and_interface()

        mac_count  = len([r for r in cfg.get("mac_rules", []) if r.get("enabled")])
        site_count = len([v for v in cfg.get("blocked_domains", {}).values() if v.get("enabled")])

        if site_count > 0 or mac_count > 0:
            self._fw_state_label.setText("ACTIVO — reglas configuradas")
            self._fw_state_label.setStyleSheet(
                "color: #22c55e; font-size: 20px; font-weight: 700; background: transparent;"
            )
        else:
            self._fw_state_label.setText("INACTIVO — sin reglas configuradas")
            self._fw_state_label.setStyleSheet(
                "color: #ef4444; font-size: 20px; font-weight: 700; background: transparent;"
            )

        def set_grid(key, value, ok):
            lbl = self._grid_widgets.get(key)
            if lbl:
                color = "#22c55e" if ok else "#ef4444"
                lbl.setText(value)
                lbl.setStyleSheet(
                    f"color: {color}; font-weight: 600; font-size: 12px; background: transparent;"
                )

        set_grid("mode",       "Administración" if mode == "admin" else "Demostración", mode == "admin")
        set_grid("ip_forward", "Activo" if info.get("ip_forward") else "Inactivo",      bool(info.get("ip_forward")))
        set_grid("iptables",   "Disponible" if info["has_iptables"] else "No encontrado", info["has_iptables"])
        set_grid("root",       "root" if info["is_root"] else "usuario normal",          info["is_root"])

        lan = cfg.get("interfaces", {}).get("lan", "")
        set_grid("iface", lan if lan else "No configurada", bool(lan))

        srv = cfg.get("server_ip", "")
        set_grid("server_ip", srv if srv else "No configurada", bool(srv))

        rejected_today = logging_service.count_rejected_today()
        for key, val in [
            ("MACs bloqueadas",   str(mac_count)),
            ("Sitios bloqueados", str(site_count)),
            ("Paquetes hoy",      str(rejected_today)),
        ]:
            if key in self._stat_widgets:
                self._stat_widgets[key].setText(val)

        self._refresh_log_rows()

    def _refresh_log_rows(self):
        while self._log_rows_layout.count():
            item = self._log_rows_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        entries = logging_service.read_log_tail(5)
        if not entries:
            empty = QLabel("Sin registros aún. Los paquetes rechazados aparecerán aquí.")
            empty.setObjectName("label_hint")
            empty.setContentsMargins(8, 6, 8, 6)
            self._log_rows_layout.addWidget(empty)
            return

        for entry in entries:
            row = QWidget()
            row.setObjectName("card_inner")
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(8, 5, 8, 5)
            row_layout.setSpacing(0)

            def cell(text, stretch, color="#8AAABB"):
                lbl = QLabel(text)
                lbl.setStyleSheet(
                    f"color: {color}; font-size: 11px; "
                    "font-family: 'Consolas','Courier New',monospace; background: transparent;"
                )
                row_layout.addWidget(lbl, stretch=stretch)

            cell(entry.get("time",  ""), 2)
            cell(entry.get("src",   ""), 3, "#E2EAFA")
            cell(entry.get("dst",   ""), 3)
            cell(entry.get("proto", ""), 1)
            reason = entry.get("reason", "")
            cell(reason, 3, "#ef4444" if reason in ("Facebook", "YouTube", "Hotmail") else "#555555")
            self._log_rows_layout.addWidget(row)

    # ─── PÚBLICA ─────────────────────────────────────────────────────────────
    def mark_applied(self):
        """Llamado desde MainWindow tras aplicar reglas exitosamente."""
        self._fw_state_label.setText("ACTIVO — reglas aplicadas en iptables")
        self._fw_state_label.setStyleSheet(
            "color: #22c55e; font-size: 20px; font-weight: 700; background: transparent;"
        )

    def update_config(self, config: dict):
        self._config = config
        self._refresh()
