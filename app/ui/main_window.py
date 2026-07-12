"""
Ventana principal M-FIREWALL
PySide6 — tema oscuro — barra lateral fija — scroll correcto
"""

from pathlib import Path
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QFrame, QScrollArea,
    QStackedWidget, QProgressBar, QSizePolicy, QMessageBox,
)
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QSize, Signal
from PySide6.QtGui import QFont, QPalette, QColor

from app.constants import (
    APP_NAME, APP_VERSION, NAV_ITEMS,
    WINDOW_WIDTH, WINDOW_HEIGHT, WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT,
    SIDEBAR_WIDTH, HEADER_HEIGHT, FOOTER_HEIGHT,
)
from app.core.platform_detector import get_mode, get_system_info
from app.core.configuration import save_config
from app.services import network_service
from app.workers.apply_worker import ApplyWorker, ValidateWorker

from app.ui.pages.dashboard_page import DashboardPage
from app.ui.pages.websites_page import WebsitesPage
from app.ui.pages.clisrv_page import CliSrvPage
from app.ui.pages.mac_page import MacPage
from app.ui.pages.connections_page import ConnectionsPage
from app.ui.pages.logs_page import LogsPage
from app.ui.pages.backups_page import BackupsPage
from app.ui.pages.settings_page import SettingsPage


def _load_stylesheet() -> str:
    qss_path = Path(__file__).parent.parent / "resources" / "styles" / "main.qss"
    if qss_path.exists():
        return qss_path.read_text(encoding="utf-8")
    return ""


class MainWindow(QMainWindow):
    def __init__(self, config: dict):
        super().__init__()
        self._config = config
        self._mode = get_mode()
        self._apply_worker = None
        self._validate_worker = None
        self._current_page_id = "dashboard"
        self._scroll_positions: dict[str, int] = {}
        self._nav_buttons: dict[str, QPushButton] = {}

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(WINDOW_WIDTH, WINDOW_HEIGHT)
        self.setMinimumSize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        self.setStyleSheet(_load_stylesheet())

        self._build_ui()
        self._navigate("dashboard")

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Header
        root_layout.addWidget(self._build_header())

        # Body: sidebar + content
        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        body_layout.addWidget(self._build_sidebar())
        body_layout.addWidget(self._build_content(), stretch=1)
        root_layout.addWidget(body, stretch=1)

        # Footer
        root_layout.addWidget(self._build_footer())

    # ── HEADER ──────────────────────────────────────────────────────────────
    def _build_header(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("header")
        frame.setFixedHeight(HEADER_HEIGHT)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(12)

        self._header_title = QLabel("Inicio")
        self._header_title.setObjectName("header_title")
        layout.addWidget(self._header_title)
        layout.addStretch()

        # Indicador de modo (sutil, sin fondo verde gritón)
        dot_color = "#3CB371" if self._mode == "admin" else "#D6A343"
        mode_text = "Administracion" if self._mode == "admin" else "Demostracion"
        badge = QLabel(f"<span style='color:{dot_color}; font-size:10px;'>&#9679;</span>"
                       f"<span style='color:#989FAB; font-size:12px;'> {mode_text}</span>")
        badge.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(badge)

        # Info IP
        own_ip, iface = network_service.get_own_ip_and_interface()
        info_text = f"IP: {own_ip}   Interfaz: {iface}"
        info_lbl = QLabel(info_text)
        info_lbl.setObjectName("header_info_label")
        layout.addWidget(info_lbl)

        return frame

    # ── SIDEBAR ─────────────────────────────────────────────────────────────
    def _build_sidebar(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("sidebar")
        frame.setFixedWidth(SIDEBAR_WIDTH)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 24, 0, 20)
        layout.setSpacing(1)

        # Logo
        logo_lbl = QLabel(APP_NAME)
        logo_lbl.setObjectName("sidebar_logo_label")
        logo_lbl.setContentsMargins(16, 0, 16, 0)
        layout.addWidget(logo_lbl)

        ver_lbl = QLabel(f"v{APP_VERSION}  |  iptables / ipset")
        ver_lbl.setObjectName("sidebar_version_label")
        ver_lbl.setContentsMargins(16, 0, 16, 0)
        layout.addWidget(ver_lbl)

        layout.addSpacing(20)

        # Botones de navegación
        for item in NAV_ITEMS:
            btn = QPushButton(f"  {item['label']}")
            btn.setObjectName("nav_btn")
            btn.setMinimumHeight(38)
            btn.clicked.connect(lambda _, page_id=item["id"]: self._navigate(page_id))
            layout.addWidget(btn)
            self._nav_buttons[item["id"]] = btn

        layout.addStretch()

        # Autores al fondo — minimalista
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)
        layout.addSpacing(8)

        for author in ["Quezada F.", "Espinola M.", "Sanchez L."]:
            lbl = QLabel(author)
            lbl.setObjectName("sidebar_author_label")
            lbl.setContentsMargins(16, 0, 16, 0)
            layout.addWidget(lbl)

        return frame

    # ── CONTENT (stacked pages) ──────────────────────────────────────────────
    def _build_content(self) -> QWidget:
        self._stack = QStackedWidget()
        self._pages: dict[str, QWidget] = {}

        page_classes = {
            "dashboard":   (DashboardPage,   self._config),
            "websites":    (WebsitesPage,     self._config),
            "clisrv":      (CliSrvPage,       self._config),
            "mac":         (MacPage,          self._config),
            "connections": (ConnectionsPage,  self._config),
            "logs":        (LogsPage,         self._config),
            "backups":     (BackupsPage,      self._config),
            "settings":    (SettingsPage,     self._config),
        }

        for page_id, (cls, cfg) in page_classes.items():
            page = cls(cfg)
            if hasattr(page, "config_changed"):
                page.config_changed.connect(self._on_config_changed)
            # Botón Aplicar del dashboard conectado al método de la ventana
            if page_id == "dashboard" and hasattr(page, "navigate_requested"):
                page.navigate_requested.connect(self._navigate)
            self._pages[page_id] = page
            self._stack.addWidget(page)

        return self._stack

    # ── FOOTER ──────────────────────────────────────────────────────────────
    def _build_footer(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("footer")
        frame.setFixedHeight(FOOTER_HEIGHT)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(10)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setFixedWidth(200)
        self._progress_bar.setVisible(False)
        layout.addWidget(self._progress_bar)

        self._status_label = QLabel("")
        self._status_label.setObjectName("label_secondary")
        layout.addWidget(self._status_label)
        layout.addStretch()

        btn_reset = QPushButton("Resetear iptables")
        btn_reset.setObjectName("btn_danger")
        btn_reset.setToolTip("Elimina TODAS las reglas iptables activas — tráfico queda abierto")
        btn_reset.clicked.connect(self._reset_iptables)
        if self._mode == "demo":
            btn_reset.setEnabled(False)
        layout.addWidget(btn_reset)

        self._btn_apply = QPushButton("Aplicar reglas")
        self._btn_apply.setObjectName("btn_primary")
        self._btn_apply.clicked.connect(self._apply_rules)
        if self._mode == "demo":
            self._btn_apply.setEnabled(False)
            self._btn_apply.setToolTip("Disponible solo en Kali Linux con iptables.")
        layout.addWidget(self._btn_apply)

        return frame

    # ── NAVEGACIÓN ───────────────────────────────────────────────────────────
    def _navigate(self, page_id: str):
        page = self._pages.get(page_id)
        if not page:
            return

        # Guardar posición scroll actual
        self._current_page_id = page_id

        # Actualizar botones
        for pid, btn in self._nav_buttons.items():
            btn.setProperty("active", pid == page_id)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

        # Cambiar página
        self._stack.setCurrentWidget(page)

        # Actualizar título header
        label = next((item["label"] for item in NAV_ITEMS if item["id"] == page_id), page_id)
        self._header_title.setText(label)

    # ── CONFIG CHANGED ───────────────────────────────────────────────────────
    def _on_config_changed(self, new_config: dict):
        self._config = new_config
        save_config(new_config)
        # Propagar a todas las páginas
        for page in self._pages.values():
            if hasattr(page, "update_config"):
                page.update_config(new_config)
        self._status_label.setText("Configuración guardada.")

    # ── APLICAR REGLAS ───────────────────────────────────────────────────────
    def _apply_rules(self):
        if self._apply_worker and self._apply_worker.isRunning():
            return
        reply = QMessageBox.question(
            self, "Aplicar reglas",
            f"Se aplicarán las reglas configuradas sobre {self._config.get('interfaces', {}).get('lan', 'la interfaz LAN')}.\n"
            "Se creará una copia de seguridad antes de continuar.\n\n¿Continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._btn_apply.setEnabled(False)
        self._status_label.setText("Iniciando...")

        self._apply_worker = ApplyWorker(self._config)
        self._apply_worker.progress.connect(self._on_progress)
        self._apply_worker.finished.connect(self._on_apply_finished)
        self._apply_worker.start()

    def _on_progress(self, pct: int, msg: str):
        self._progress_bar.setValue(pct)
        self._status_label.setText(msg)

    def _on_apply_finished(self, ok: bool, msg: str):
        self._progress_bar.setVisible(False)
        self._btn_apply.setEnabled(self._mode == "admin")
        self._status_label.setText(msg)
        if ok:
            QMessageBox.information(self, "Reglas aplicadas", msg)
        else:
            QMessageBox.warning(self, "Error al aplicar", msg)

    def _validate_rules(self):
        if self._validate_worker and self._validate_worker.isRunning():
            return
        self._status_label.setText("Validando configuración...")
        self._validate_worker = ValidateWorker(self._config)
        self._validate_worker.finished.connect(
            lambda ok, msg: self._status_label.setText(f"{'✓' if ok else '✗'} {msg}")
        )
        self._validate_worker.start()

    def _restore_last(self):
        backups = __import__("app.services.firewall_service", fromlist=["list_backups"]).list_backups()
        if not backups:
            QMessageBox.information(self, "Sin copias", "No hay copias de seguridad disponibles.")
            return
        last = backups[0]
        reply = QMessageBox.question(
            self, "Restaurar",
            f"Restaurar copia del {last['date']} ({last['rule_count']} reglas)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            from app.services import firewall_service
            ok, msg = firewall_service.restore_backup(last["path"])
            self._status_label.setText(msg)

    def _reset_iptables(self):
        reply = QMessageBox.warning(
            self, "Resetear iptables",
            "Esto eliminará TODAS las reglas iptables activas.\n"
            "El tráfico quedará completamente abierto hasta que vuelvas a aplicar reglas.\n\n"
            "¿Continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        from app.services import firewall_service
        ok, msg = firewall_service.flush_all()
        self._status_label.setText(msg)
        if ok:
            QMessageBox.information(self, "Reglas eliminadas", msg)
        else:
            QMessageBox.warning(self, "Error", msg)
