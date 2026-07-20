"""
Ventana principal M-FIREWALL
PySide6 — Proyecto M: Quezada / Espinola / Sanchez
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
    LINUX_RULES_FILE,
)
from app.core.platform_detector import get_mode
from app.core.configuration import save_config
from app.services import network_service
from app.workers.apply_worker import ApplyWorker

from app.ui.pages.websites_page import WebsitesPage
from app.ui.pages.clisrv_page import CliSrvPage
from app.ui.pages.mac_page import MacPage
from app.ui.pages.connections_page import ConnectionsPage
from app.ui.pages.logs_page import LogsPage
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
        self._pending_changes = False

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} — Administrador de Firewall")
        self.resize(WINDOW_WIDTH, WINDOW_HEIGHT)
        self.setMinimumSize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        self.setStyleSheet(_load_stylesheet())

        self._build_ui()

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(10)

        # ── Header ──────────────────────────────────────────────
        root_layout.addWidget(self._build_header())

        # ── Pestañas ─────────────────────────────────────────────
        self._tabs = QTabWidget()
        root_layout.addWidget(self._tabs, stretch=1)

        self._pages = {}
        page_classes = [
            ("Sitios Web",         WebsitesPage),
            ("Cliente / Servidor", CliSrvPage),
            ("Bloqueo MAC",        MacPage),
            ("Conexiones",         ConnectionsPage),
            ("Registros",          LogsPage),
            ("Configuracion",      SettingsPage),
        ]

        for title, cls in page_classes:
            page = cls(self._config)
            if hasattr(page, "config_changed"):
                page.config_changed.connect(self._on_config_changed)
            self._tabs.addTab(page, title)
            self._pages[title] = page

        # ── Footer ──────────────────────────────────────────────
        root_layout.addWidget(self._build_footer())

    def _build_header(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(12)

        # Título
        title_lbl = QLabel(f"{APP_NAME}")
        title_lbl.setStyleSheet(
            "font-size: 16px; font-weight: 700; color: #3b82f6; background: transparent;"
        )
        layout.addWidget(title_lbl)

        # Info de red
        own_ip, iface = network_service.get_own_ip_and_interface()
        mode_text = "Administracion" if self._mode == "admin" else "Demo"
        info_lbl = QLabel(
            f"{mode_text}   |   IP: {own_ip}   |   Interfaz: {iface}"
        )
        info_lbl.setObjectName("label_secondary")
        layout.addWidget(info_lbl)

        layout.addStretch()

        # Ruta del archivo de reglas
        rules_path = self._config.get("rules_file", "") or LINUX_RULES_FILE
        rules_lbl = QLabel(f"Reglas: {rules_path}")
        rules_lbl.setObjectName("label_hint")
        layout.addWidget(rules_lbl)
        self._rules_path_lbl = rules_lbl

        # Versión
        ver_lbl = QLabel(f"v{APP_VERSION}")
        ver_lbl.setObjectName("label_secondary")
        layout.addWidget(ver_lbl)

        return frame

    def _build_footer(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(10)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setFixedWidth(180)
        self._progress_bar.setVisible(False)
        layout.addWidget(self._progress_bar)

        # Status
        self._status_label = QLabel("Listo.")
        self._status_label.setObjectName("label_secondary")
        layout.addWidget(self._status_label, stretch=1)

        # Autores
        authors_lbl = QLabel("Quezada · Espinola · Sanchez")
        authors_lbl.setObjectName("label_hint")
        authors_lbl.setStyleSheet("color: #3a4050; background: transparent;")
        layout.addWidget(authors_lbl)

        # Botón limpiar iptables
        btn_reset = QPushButton("Apagar Firewall")
        btn_reset.setObjectName("btn_reset_firewall")
        btn_reset.setStyleSheet("background-color: #3b111a; border-color: #551e24; color: #f87171;")
        btn_reset.setToolTip("Desactiva temporalmente el firewall y vuelve a permitir todo el tráfico.")
        btn_reset.clicked.connect(self._reset_iptables)
        if self._mode == "demo":
            btn_reset.setEnabled(False)
        layout.addWidget(btn_reset)

        # Botón Aplicar reglas (el más importante)
        self._btn_apply = QPushButton("Activar Firewall")
        self._btn_apply.setObjectName("btn_apply")
        self._btn_apply.setToolTip(
            "Carga y activa el bloqueo de sitios web, limitaciones y reglas en el sistema.\n"
            f"Guarda las reglas en: {self._config.get('rules_file', '') or LINUX_RULES_FILE}"
        )
        self._btn_apply.clicked.connect(self._apply_rules)
        if self._mode == "demo":
            self._btn_apply.setEnabled(False)
            self._btn_apply.setToolTip("Disponible solo en Kali Linux con root.")
        layout.addWidget(self._btn_apply)

        return frame

    def _on_config_changed(self, new_config: dict):
        self._config = new_config
        save_config(new_config)
        for page in self._pages.values():
            if hasattr(page, "update_config"):
                page.update_config(new_config)
        
        # Actualizar la configuración del proxy DNS en tiempo real
        try:
            from app.services.dns_proxy_service import get_dns_proxy
            get_dns_proxy().update_config(new_config)
        except Exception:
            pass

        self._status_label.setText("Configuracion guardada.")
        self._pending_changes = True
        self._btn_apply.setText("Guardar y Activar *")
        # Actualizar ruta en header
        rules_path = new_config.get("rules_file", "") or LINUX_RULES_FILE
        self._rules_path_lbl.setText(f"Reglas: {rules_path}")

    def _apply_rules(self):
        if self._apply_worker and self._apply_worker.isRunning():
            return

        # Verificar que hay algo para aplicar
        blocked = self._config.get("blocked_domains", {})
        has_sites = any(v.get("enabled", False) for v in blocked.values())
        has_mac = any(r.get("enabled", False) for r in self._config.get("mac_rules", []))
        has_conn = any(p.get("enabled", False) for p in self._config.get("conn_profiles", []))
        has_clisrv = self._config.get("clisrv", {}).get("enabled", False)

        if not any([has_sites, has_mac, has_conn, has_clisrv]):
            QMessageBox.information(
                self, "Sin bloqueos configurados",
                "No has activado ningún bloqueo.\n\n"
                "Ve a las pestañas superiores (Sitios Web, Bloqueo MAC, etc.) "
                "y activa al menos una casilla antes de Activar el Firewall.",
            )
            return

        lan_iface = self._config.get("interfaces", {}).get("lan", "la interfaz LAN")
        rules_path = self._config.get("rules_file", "") or LINUX_RULES_FILE

        reply = QMessageBox.question(
            self, "Activar Firewall",
            f"Se aplicarán las reglas de bloqueo sobre la interfaz <b>{lan_iface}</b>.\n"
            f"El archivo se guardará en:\n<b>{rules_path}</b>\n\n"
            "¿Deseas activar el firewall ahora?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        from app.ui.dialogs.progress_dialog import ApplyProgressDialog
        dialog = ApplyProgressDialog(self._config, self)
        # Mostrar de forma modal e iniciar la ejecución secuencial en segundo plano
        dialog.start_execution()
        dialog.exec()

        # Al cerrarse el diálogo, refrescamos el estado de las pestañas
        self._pending_changes = False
        self._btn_apply.setText("Activar Firewall")
        for page in self._pages.values():
            if hasattr(page, "_verify_all"):
                page._verify_all()

    def _reset_iptables(self):
        reply = QMessageBox.warning(
            self, "Apagar Firewall",
            "¿Estás seguro de que deseas desactivar el firewall?\n"
            "Esto detendrá todos los bloqueos y los sitios volverán a ser accesibles inmediatamente.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        from app.services import firewall_service
        ok, msg = firewall_service.flush_all()
        self._status_label.setText("Firewall apagado.")
        if ok:
            QMessageBox.information(self, "Firewall apagado", "Se han eliminado todas las reglas. El tráfico está libre.")
        else:
            QMessageBox.warning(self, "Error", msg)
