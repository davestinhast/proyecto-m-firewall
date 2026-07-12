"""
Pantalla 1 — Inicio / Dashboard
Checklist guiado + datos del sistema en tiempo real.
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
    navigate_requested = Signal(str)   # emitido cuando el usuario pulsa "Ir →" en un paso

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
        self._layout.setSpacing(12)

        # Título
        title = QLabel("M-FIREWALL")
        title.setObjectName("label_title")
        subtitle = QLabel("Administrador de reglas iptables para Kali Linux")
        subtitle.setObjectName("label_secondary")
        self._layout.addWidget(title)
        self._layout.addWidget(subtitle)
        self._layout.addSpacing(8)

        # Estado del sistema
        self._layout.addWidget(self._build_system_bar())
        self._layout.addSpacing(4)

        # Checklist de configuración
        self._checklist_header_widget = self._build_checklist_header()
        self._layout.addWidget(self._checklist_header_widget)
        self._checklist_frame = self._build_checklist()
        self._layout.addWidget(self._checklist_frame)
        self._layout.addSpacing(4)

        # Estadísticas rápidas
        self._layout.addWidget(self._build_stats_row())
        self._layout.addSpacing(4)

        # Últimos rechazados
        self._layout.addWidget(self._build_log_preview())

        # Integrantes
        self._layout.addSpacing(8)
        self._layout.addWidget(self._build_footer_info())

        self._layout.addStretch()
        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    # ─── BARRA ESTADO SISTEMA ────────────────────────────────────────────────
    def _build_system_bar(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(0)

        info = get_system_info()
        mode = get_mode()
        own_ip, iface = network_service.get_own_ip_and_interface()

        def col(label: str, value: str, value_color: str = "#E2EAFA"):
            w = QWidget()
            w.setObjectName("card_inner")
            l = QVBoxLayout(w)
            l.setContentsMargins(0, 0, 0, 0)
            l.setSpacing(2)
            lbl_k = QLabel(label)
            lbl_k.setObjectName("label_hint")
            lbl_v = QLabel(value)
            lbl_v.setStyleSheet(f"color: {value_color}; font-weight: 600; font-size: 12px; background: transparent;")
            l.addWidget(lbl_k)
            l.addWidget(lbl_v)
            return w

        dot_color = "#22c55e" if mode == "admin" else "#f59e0b"
        mode_label = "Administracion (Kali Linux)" if mode == "admin" else "Demostracion (Windows)"

        layout.addWidget(col("Modo", mode_label, dot_color))
        layout.addSpacing(32)
        layout.addWidget(col("IP detectada", own_ip))
        layout.addSpacing(32)
        layout.addWidget(col("Interfaz", iface))
        layout.addSpacing(32)
        layout.addWidget(col("iptables", "Disponible" if info["has_iptables"] else "No encontrado",
                             "#22c55e" if info["has_iptables"] else "#ef4444"))
        layout.addSpacing(32)
        layout.addWidget(col("Permisos", "root" if info["is_root"] else "usuario normal",
                             "#22c55e" if info["is_root"] else "#f59e0b"))
        layout.addSpacing(32)
        ip_fwd = info.get("ip_forward", False)
        layout.addWidget(col("IP Forward", "Activo" if ip_fwd else "Inactivo",
                             "#22c55e" if ip_fwd else "#ef4444"))
        layout.addStretch()

        # Estado firewall
        self._fw_status_label = QLabel("INACTIVO")
        self._fw_status_label.setStyleSheet(
            "color: #ef4444; font-size: 11px; font-weight: 700; "
            "border: 1px solid #3f1515; border-radius: 3px; "
            "padding: 3px 10px; background: transparent;"
        )
        layout.addWidget(self._fw_status_label)

        return frame

    # ─── CHECKLIST ───────────────────────────────────────────────────────────
    def _build_checklist_header(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 4)
        l.setSpacing(4)

        row = QHBoxLayout()
        lbl = QLabel("Pasos de configuracion")
        lbl.setObjectName("label_subtitle")
        row.addWidget(lbl)
        row.addStretch()
        self._progress_lbl = QLabel("0 / 6 completados")
        self._progress_lbl.setStyleSheet(
            "color: #8AAABB; font-size: 12px; font-weight: 600; background: transparent;"
        )
        row.addWidget(self._progress_lbl)
        l.addLayout(row)

        hint = QLabel("Haz clic en cualquier paso para ir directo a esa pantalla. "
                      "Cuando esten todos en verde, pulsa 'Aplicar reglas' abajo a la derecha.")
        hint.setObjectName("label_secondary")
        hint.setWordWrap(True)
        l.addWidget(hint)
        return w

    def _build_checklist(self) -> QWidget:
        self._step_frames = []
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        steps = [
            {
                "num": "01",
                "title": "Configurar interfaces de red",
                "desc": "Indica cual interfaz conecta con Internet (WAN) y cual conecta con los clientes (LAN). "
                        "Sin esto, las reglas no saben por donde filtrar el trafico.",
                "page": "settings",
                "check": lambda c: bool(c.get("interfaces", {}).get("lan")),
            },
            {
                "num": "02",
                "title": "Definir IP del servidor y del cliente",
                "desc": "Ingresa la IP de esta maquina Kali (servidor) y la IP del cliente que quieres controlar. "
                        "Esto permite el bloqueo unidireccional.",
                "page": "settings",
                "check": lambda c: bool(c.get("server_ip")),
            },
            {
                "num": "03",
                "title": "Activar bloqueo de sitios web",
                "desc": "Activa Facebook, YouTube y/o Hotmail para bloquearlos. "
                        "La aplicacion resuelve sus IPs automaticamente y bloquea TCP 80, TCP 443 y UDP 443.",
                "page": "websites",
                "check": lambda c: any(
                    v.get("enabled") for v in c.get("blocked_domains", {}).values()
                ),
            },
            {
                "num": "04",
                "title": "Configurar bloqueo cliente a servidor",
                "desc": "Bloquea las conexiones nuevas del cliente hacia el servidor. "
                        "El servidor si puede iniciar conexiones hacia el cliente. Requiere las IPs del paso 02.",
                "page": "clisrv",
                "check": lambda c: c.get("clisrv", {}).get("enabled", False),
            },
            {
                "num": "05",
                "title": "Agregar equipos a bloquear por MAC",
                "desc": "Escanea la red local, selecciona los equipos y bloquealos por su direccion MAC. "
                        "Funciona mientras el cliente este en la misma red que Kali.",
                "page": "mac",
                "check": lambda c: bool(c.get("mac_rules")),
            },
            {
                "num": "06",
                "title": "Configurar limite de conexiones simultaneas",
                "desc": "Activa los perfiles SSH, HTTP y HTTPS para limitar cuantas conexiones puede abrir "
                        "un mismo equipo al mismo tiempo.",
                "page": "connections",
                "check": lambda c: any(
                    p.get("enabled") for p in c.get("conn_profiles", [])
                ),
            },
            {
                "num": "07",
                "title": "Aplicar todas las reglas",
                "desc": "Usa el boton 'Aplicar reglas' en la barra inferior. Se validaran las reglas, "
                        "se creara una copia de seguridad automatica y se cargaran en iptables.",
                "page": None,
                "check": lambda c: False,  # nunca verde hasta que se aplique manualmente
            },
        ]

        self._step_data = steps
        for step in steps:
            frame = self._build_step_card(step, done=False)
            layout.addWidget(frame)
            self._step_frames.append(frame)

        return container

    def _build_step_card(self, step: dict, done: bool) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card_step_done" if done else "card_step_pending")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(14)

        # Numero
        num_lbl = QLabel(step["num"])
        num_lbl.setObjectName("step_number_done" if done else "step_number")
        num_lbl.setFixedWidth(26)
        num_lbl.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(num_lbl)

        # Contenido
        content = QWidget()
        content.setObjectName("card_inner")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)

        title_lbl = QLabel(step["title"])
        if done:
            title_lbl.setStyleSheet("color: #22C55E; font-weight: 600; font-size: 13px; background: transparent;")
        else:
            title_lbl.setStyleSheet("color: #E2EAFA; font-weight: 600; font-size: 13px; background: transparent;")

        desc_lbl = QLabel(step["desc"])
        desc_lbl.setObjectName("label_secondary")
        desc_lbl.setWordWrap(True)

        content_layout.addWidget(title_lbl)
        content_layout.addWidget(desc_lbl)
        layout.addWidget(content, stretch=1)

        # Derecha: badge + botón Ir (si tiene página destino)
        right = QWidget()
        right.setObjectName("card_inner")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)
        right_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight)

        if done:
            status_lbl = QLabel("✓ Listo")
            status_lbl.setObjectName("label_tag_active")
        else:
            status_lbl = QLabel("Pendiente")
            status_lbl.setObjectName("label_tag_inactive")
        right_layout.addWidget(status_lbl)

        page_id = step.get("page")
        if page_id:
            btn_go = QPushButton("Ir →")
            btn_go.setObjectName("btn_secondary")
            btn_go.setFixedWidth(60)
            btn_go.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            btn_go.clicked.connect(lambda _, pid=page_id: self.navigate_requested.emit(pid))
            right_layout.addWidget(btn_go)

        layout.addWidget(right)
        return frame

    def _rebuild_checklist(self):
        """Destruye y reconstruye las tarjetas de paso con estado actualizado."""
        while self._checklist_frame.layout().count():
            item = self._checklist_frame.layout().takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._step_frames.clear()

        done_count = 0
        # Solo los pasos 1-6 cuentan (el 7 es manual, nunca verde)
        countable = [s for s in self._step_data if s.get("page") is not None]
        for step in self._step_data:
            done = step["check"](self._config)
            if done and step.get("page") is not None:
                done_count += 1
            frame = self._build_step_card(step, done=done)
            self._checklist_frame.layout().addWidget(frame)
            self._step_frames.append(frame)

        total = len(countable)
        if done_count == total:
            color = "#22c55e"
            text = f"✓ {done_count} / {total} completados — listo para aplicar"
        else:
            color = "#8AAABB"
            text = f"{done_count} / {total} completados"

        if hasattr(self, "_progress_lbl"):
            self._progress_lbl.setStyleSheet(
                f"color: {color}; font-size: 12px; font-weight: 600; background: transparent;"
            )
            self._progress_lbl.setText(text)

    # ─── STATS ───────────────────────────────────────────────────────────────
    def _build_stats_row(self) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._stat_widgets = {}

        stats = [
            ("Reglas activas",     "0",  "#e5e5e5"),
            ("MACs bloqueadas",    "0",  "#e5e5e5"),
            ("Sitios bloqueados",  "0",  "#e5e5e5"),
            ("Paquetes hoy",       "0",  "#e5e5e5"),
        ]

        for label, value, color in stats:
            card = QFrame()
            card.setObjectName("card")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(16, 14, 16, 14)
            card_layout.setSpacing(3)

            val_lbl = QLabel(value)
            val_lbl.setStyleSheet(
                f"color: {color}; font-size: 22px; font-weight: 700; background: transparent;"
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
        lbl = QLabel("Ultimos paquetes rechazados")
        lbl.setObjectName("label_subtitle")
        hdr.addWidget(lbl)
        hdr.addStretch()
        hint = QLabel("Se actualiza cada 6 segundos")
        hint.setObjectName("label_hint")
        hdr.addWidget(hint)
        layout.addLayout(hdr)

        # Cabecera tabla manual
        header_row = QWidget()
        header_row.setObjectName("card_inner")
        header_layout = QHBoxLayout(header_row)
        header_layout.setContentsMargins(8, 4, 8, 4)
        header_layout.setSpacing(0)
        for col_name, stretch in [("Hora", 2), ("Origen", 3), ("Destino", 3), ("Proto", 1), ("Motivo", 3)]:
            h = QLabel(col_name.upper())
            h.setObjectName("label_hint")
            h.setStyleSheet("color: #5C7A95; font-size: 10px; font-weight: 700; letter-spacing: 1px; background: transparent;")
            header_layout.addWidget(h, stretch=stretch)
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
        mac_count = len([r for r in cfg.get("mac_rules", []) if r.get("enabled")])
        site_count = len([v for v in cfg.get("blocked_domains", {}).values() if v.get("enabled")])
        rejected_today = logging_service.count_rejected_today()

        # Stats
        vals = {
            "Reglas activas": "—",
            "MACs bloqueadas": str(mac_count),
            "Sitios bloqueados": str(site_count),
            "Paquetes hoy": str(rejected_today),
        }
        for key, val in vals.items():
            if key in self._stat_widgets:
                self._stat_widgets[key].setText(val)

        # Checklist
        self._rebuild_checklist()

        # Log preview
        self._refresh_log_rows()

    def _refresh_log_rows(self):
        # limpiar filas anteriores
        while self._log_rows_layout.count():
            item = self._log_rows_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        entries = logging_service.read_log_tail(5)
        if not entries:
            empty = QLabel("Sin registros aun. Los paquetes rechazados apareceran aqui.")
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
                lbl.setStyleSheet(f"color: {color}; font-size: 11px; font-family: 'Consolas','Courier New',monospace; background: transparent;")
                row_layout.addWidget(lbl, stretch=stretch)

            cell(entry.get("time", ""), 2)
            cell(entry.get("src", ""), 3, "#E2EAFA")
            cell(entry.get("dst", ""), 3)
            cell(entry.get("proto", ""), 1)

            reason = entry.get("reason", "")
            reason_color = "#ef4444" if reason in ("Facebook", "YouTube", "Hotmail") else "#555555"
            cell(reason, 3, reason_color)

            self._log_rows_layout.addWidget(row)

    def update_config(self, config: dict):
        self._config = config
        self._refresh()
