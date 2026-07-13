"""
Ventana principal M-FIREWALL
PySide6 — diseño clásico para proyecto universitario
"""

from pathlib import Path
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QFrame, QTabWidget, QProgressBar, QMessageBox,
)
from PySide6.QtCore import Qt

from app.constants import (
    APP_NAME, APP_VERSION,
    WINDOW_WIDTH, WINDOW_HEIGHT, WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT,
)
from app.core.platform_detector import get_mode
from app.core.configuration import save_config
from app.services import network_service
from app.workers.apply_worker import ApplyWorker, ValidateWorker

from app.ui.pages.websites_page import WebsitesPage
from app.ui.pages.clisrv_page import CliSrvPage
from app.ui.pages.mac_page import MacPage
from app.ui.pages.connections_page import ConnectionsPage
from app.ui.pages.logs_page import LogsPage
from app.ui.pages.settings_page import SettingsPage


class MainWindow(QMainWindow):
    def __init__(self, config: dict):
        super().__init__()
        self._config = config
        self._mode = get_mode()
        self._apply_worker = None
        self._validate_worker = None
        self._pending_changes = False

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} - Administrador de Reglas")
        self.resize(WINDOW_WIDTH, WINDOW_HEIGHT)
        self.setMinimumSize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)

        self._build_ui()

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(10, 10, 10, 10)
        root_layout.setSpacing(10)

        # Header info
        own_ip, iface = network_service.get_own_ip_and_interface()
        mode_text = "Administración" if self._mode == "admin" else "Demostración"
        info_lbl = QLabel(f"Modo: {mode_text} | IP Servidor: {own_ip} | Interfaz: {iface}")
        root_layout.addWidget(info_lbl)

        # Tabs (reemplaza Sidebar)
        self._tabs = QTabWidget()
        root_layout.addWidget(self._tabs, stretch=1)

        self._pages = {}
        
        page_classes = [
            ("Sitios Web", WebsitesPage),
            ("Cliente / Servidor", CliSrvPage),
            ("Bloqueo MAC", MacPage),
            ("Conexiones", ConnectionsPage),
            ("Registros", LogsPage),
            ("Configuración", SettingsPage),
        ]

        for title, cls in page_classes:
            page = cls(self._config)
            if hasattr(page, "config_changed"):
                page.config_changed.connect(self._on_config_changed)
            self._tabs.addTab(page, title)
            self._pages[title] = page

        # Footer
        root_layout.addWidget(self._build_footer())

    def _build_footer(self) -> QFrame:
        frame = QFrame()
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(0, 5, 0, 0)
        
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setFixedWidth(200)
        self._progress_bar.setVisible(False)
        layout.addWidget(self._progress_bar)

        self._status_label = QLabel("Listo.")
        layout.addWidget(self._status_label)
        layout.addStretch()

        btn_reset = QPushButton("Resetear iptables")
        btn_reset.clicked.connect(self._reset_iptables)
        if self._mode == "demo":
            btn_reset.setEnabled(False)
        layout.addWidget(btn_reset)

        self._btn_apply = QPushButton("Aplicar reglas")
        self._btn_apply.clicked.connect(self._apply_rules)
        if self._mode == "demo":
            self._btn_apply.setEnabled(False)
            self._btn_apply.setToolTip("Disponible solo en Kali Linux.")
        layout.addWidget(self._btn_apply)

        return frame

    def _on_config_changed(self, new_config: dict):
        self._config = new_config
        save_config(new_config)
        for page in self._pages.values():
            if hasattr(page, "update_config"):
                page.update_config(new_config)
        self._status_label.setText("Configuración guardada.")
        self._pending_changes = True
        self._btn_apply.setText("* Aplicar cambios")

    def _apply_rules(self):
        if self._apply_worker and self._apply_worker.isRunning():
            return
        reply = QMessageBox.question(
            self, "Aplicar reglas",
            f"Se aplicarán las reglas configuradas sobre {self._config.get('interfaces', {}).get('lan', 'la interfaz LAN')}.\n"
            "¿Continuar?",
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
            self._pending_changes = False
            self._btn_apply.setText("Aplicar reglas")
            QMessageBox.information(self, "Reglas aplicadas", msg)
        else:
            QMessageBox.warning(self, "Error al aplicar", msg)

    def _reset_iptables(self):
        reply = QMessageBox.warning(
            self, "Resetear iptables",
            "Esto eliminará TODAS las reglas iptables activas.\n¿Continuar?",
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
