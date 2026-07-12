"""
Pantalla 2 — Bloqueo de sitios web
"""

import socket
import subprocess
from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QApplication, QGridLayout,
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from app.ui.widgets.toggle_switch import ToggleSwitch
from app.constants import BLOCKED_DOMAINS


# ─── WORKERS ─────────────────────────────────────────────────────────────────

class _EnableIPForwardWorker(QThread):
    finished = Signal(bool)

    def run(self):
        from app.core.platform_detector import enable_ip_forward
        ok = enable_ip_forward()
        self.finished.emit(ok)


class _FullCheckWorker(QThread):
    finished = Signal(str, int, int, bool)  # key, ip_count, rule_count, reachable

    def __init__(self, key: str, domains: list):
        super().__init__()
        self._key = key
        self._domains = domains

    def run(self):
        from app.services import domain_service

        ips = set()
        for d in self._domains:
            ips.update(domain_service.resolve_domain(d))
        ip_count = len(ips)

        rule_count = 0
        try:
            result = subprocess.run(
                ["iptables", "-L", "PM_WEBBLOCK", "-n"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                rule_count = sum(
                    1 for line in result.stdout.splitlines()
                    if "PM_REJECT" in line or "DROP" in line
                )
        except Exception:
            rule_count = -1

        reachable = False
        try:
            domain = self._domains[0] if self._domains else ""
            if domain:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((domain, 443))
                s.close()
                reachable = True
        except Exception:
            reachable = False

        self.finished.emit(self._key, ip_count, rule_count, reachable)


# ─── PREREQ CARD ─────────────────────────────────────────────────────────────

class _PrereqCard(QFrame):
    """Muestra y resuelve los requisitos para que el bloqueo funcione en clientes."""

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._ipfwd_worker = None
        self.setObjectName("card_accent_blue")
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # Header
        title_row = QHBoxLayout()
        title = QLabel("Requisitos para que el bloqueo funcione en los clientes")
        title.setObjectName("label_subtitle")
        title_row.addWidget(title)
        title_row.addStretch()
        btn_refresh = QPushButton("Verificar")
        btn_refresh.setObjectName("btn_small")
        btn_refresh.clicked.connect(self.refresh)
        title_row.addWidget(btn_refresh)
        layout.addLayout(title_row)

        # ip_forward
        ipfwd_row = QHBoxLayout()
        self._ipfwd_lbl = QLabel("IP Forward: verificando...")
        self._ipfwd_lbl.setObjectName("label_secondary")
        ipfwd_row.addWidget(self._ipfwd_lbl, stretch=1)
        self._btn_enable_ipfwd = QPushButton("Activar ahora")
        self._btn_enable_ipfwd.setObjectName("btn_success")
        self._btn_enable_ipfwd.setVisible(False)
        self._btn_enable_ipfwd.clicked.connect(self._on_enable_ipfwd)
        ipfwd_row.addWidget(self._btn_enable_ipfwd)
        layout.addLayout(ipfwd_row)

        # MASQUERADE
        self._masq_lbl = QLabel("NAT MASQUERADE: verificando...")
        self._masq_lbl.setObjectName("label_secondary")
        layout.addWidget(self._masq_lbl)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        # Gateway instructions
        gw_title = QLabel("Configurar gateway en los clientes (obligatorio)")
        gw_title.setObjectName("label_subtitle")
        layout.addWidget(gw_title)

        gw_desc = QLabel(
            "Para que iptables filtre el tráfico de los clientes, "
            "cada PC cliente debe tener la IP de esta máquina Kali como puerta de enlace. "
            "Sin eso el tráfico no pasa por aquí y el bloqueo no tiene efecto."
        )
        gw_desc.setObjectName("label_secondary")
        gw_desc.setWordWrap(True)
        layout.addWidget(gw_desc)

        gw_grid = QGridLayout()
        gw_grid.setSpacing(8)
        gw_grid.setColumnStretch(1, 1)

        win_lbl = QLabel("Windows")
        win_lbl.setObjectName("label_hint")
        self._gw_win_cmd = QLabel("—")
        self._gw_win_cmd.setWordWrap(True)
        self._gw_win_cmd.setStyleSheet(
            "background-color: #1B2A47; color: #E2EAFA; "
            "font-family: 'Consolas','Courier New',monospace; font-size: 11px; "
            "border-radius: 4px; padding: 6px 10px;"
        )
        btn_copy_win = QPushButton("Copiar")
        btn_copy_win.setObjectName("btn_small")
        btn_copy_win.clicked.connect(lambda: QApplication.clipboard().setText(self._gw_win_cmd.text()))

        lin_lbl = QLabel("Linux")
        lin_lbl.setObjectName("label_hint")
        self._gw_lin_cmd = QLabel("—")
        self._gw_lin_cmd.setStyleSheet(
            "background-color: #1B2A47; color: #22c55e; "
            "font-family: 'Consolas','Courier New',monospace; font-size: 11px; "
            "border-radius: 4px; padding: 6px 10px;"
        )
        btn_copy_lin = QPushButton("Copiar")
        btn_copy_lin.setObjectName("btn_small")
        btn_copy_lin.clicked.connect(lambda: QApplication.clipboard().setText(self._gw_lin_cmd.text()))

        gw_grid.addWidget(win_lbl,       0, 0)
        gw_grid.addWidget(self._gw_win_cmd, 0, 1)
        gw_grid.addWidget(btn_copy_win,  0, 2)
        gw_grid.addWidget(lin_lbl,       1, 0)
        gw_grid.addWidget(self._gw_lin_cmd, 1, 1)
        gw_grid.addWidget(btn_copy_lin,  1, 2)
        layout.addLayout(gw_grid)

        self.refresh()

    def refresh(self):
        from app.core.platform_detector import is_linux, has_ip_forward

        if is_linux():
            ipfwd = has_ip_forward()
            if ipfwd:
                self._ipfwd_lbl.setText("✓  IP Forward: activo — Kali reenvía paquetes entre interfaces")
                self._ipfwd_lbl.setStyleSheet("color: #22c55e; font-size: 12px; background: transparent;")
                self._btn_enable_ipfwd.setVisible(False)
            else:
                self._ipfwd_lbl.setText("✗  IP Forward: INACTIVO — los paquetes no se reenvían")
                self._ipfwd_lbl.setStyleSheet("color: #ef4444; font-size: 12px; background: transparent;")
                self._btn_enable_ipfwd.setVisible(True)
        else:
            self._ipfwd_lbl.setText("—  IP Forward: no aplica (modo demo)")
            self._ipfwd_lbl.setStyleSheet("color: #8AAABB; font-size: 12px; background: transparent;")
            self._btn_enable_ipfwd.setVisible(False)

        if is_linux():
            masq = False
            try:
                r = subprocess.run(
                    ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n"],
                    capture_output=True, text=True, timeout=5
                )
                masq = "MASQUERADE" in r.stdout
            except Exception:
                masq = False
            if masq:
                self._masq_lbl.setText("✓  NAT MASQUERADE: activo — los clientes pueden salir a Internet a través de Kali")
                self._masq_lbl.setStyleSheet("color: #22c55e; font-size: 12px; background: transparent;")
            else:
                self._masq_lbl.setText("✗  NAT MASQUERADE: falta — aplica las reglas primero (botón 'Aplicar reglas')")
                self._masq_lbl.setStyleSheet("color: #f59e0b; font-size: 12px; background: transparent;")
        else:
            self._masq_lbl.setText("—  NAT MASQUERADE: no aplica (modo demo)")
            self._masq_lbl.setStyleSheet("color: #8AAABB; font-size: 12px; background: transparent;")

        srv_ip = self._config.get("server_ip", "") or "X.X.X.X"
        self._gw_win_cmd.setText(
            f"Panel de control → Adaptador de red → TCP/IPv4 → "
            f"Puerta de enlace predeterminada: {srv_ip}"
        )
        self._gw_lin_cmd.setText(f"sudo ip route add default via {srv_ip}")

    def _on_enable_ipfwd(self):
        self._btn_enable_ipfwd.setEnabled(False)
        self._btn_enable_ipfwd.setText("Activando...")
        self._ipfwd_worker = _EnableIPForwardWorker()
        self._ipfwd_worker.finished.connect(self._on_ipfwd_done)
        self._ipfwd_worker.start()

    def _on_ipfwd_done(self, ok: bool):
        self._btn_enable_ipfwd.setEnabled(True)
        self._btn_enable_ipfwd.setText("Activar ahora")
        self.refresh()

    def update_config(self, config: dict):
        self._config = config
        srv_ip = config.get("server_ip", "") or "X.X.X.X"
        self._gw_win_cmd.setText(
            f"Panel de control → Adaptador de red → TCP/IPv4 → "
            f"Puerta de enlace predeterminada: {srv_ip}"
        )
        self._gw_lin_cmd.setText(f"sudo ip route add default via {srv_ip}")


# ─── SITE CARD ───────────────────────────────────────────────────────────────

class SiteCard(QFrame):
    toggled         = Signal(str, bool)
    check_requested = Signal(str)

    def __init__(self, key: str, cfg: dict, parent=None):
        super().__init__(parent)
        self._key = key
        self._cfg = cfg
        self.setObjectName("card")
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)

        # Top: nombre + badge + toggle
        top_row = QHBoxLayout()
        label_name = QLabel(self._cfg["label"])
        label_name.setObjectName("label_subtitle")
        top_row.addWidget(label_name)
        top_row.addSpacing(12)

        self._badge = QLabel("⚪  Sin verificar")
        self._badge.setStyleSheet(
            "color: #5C7A95; font-size: 12px; font-weight: 600; background: transparent;"
        )
        top_row.addWidget(self._badge)
        top_row.addStretch()

        self._toggle = ToggleSwitch()
        self._toggle.setChecked(self._cfg.get("enabled", False))
        self._toggle.toggled.connect(lambda checked: self.toggled.emit(self._key, checked))
        top_row.addWidget(self._toggle)
        layout.addLayout(top_row)

        # Descripción + dominios
        desc = QLabel(self._cfg.get("description", ""))
        desc.setObjectName("label_secondary")
        layout.addWidget(desc)

        domains_lbl = QLabel("  ".join(self._cfg.get("domains", [])))
        domains_lbl.setObjectName("label_secondary")
        domains_lbl.setWordWrap(True)
        layout.addWidget(domains_lbl)

        # Detail row: IPs + reglas + botón verificar
        detail_row = QHBoxLayout()
        self._ip_label = QLabel("IPs: —")
        self._ip_label.setObjectName("label_mono")
        detail_row.addWidget(self._ip_label)
        detail_row.addSpacing(24)
        self._rules_label = QLabel("Reglas iptables: —")
        self._rules_label.setObjectName("label_mono")
        detail_row.addWidget(self._rules_label)
        detail_row.addStretch()
        self._btn_check = QPushButton("Verificar ahora")
        self._btn_check.setObjectName("btn_small")
        self._btn_check.clicked.connect(lambda: self.check_requested.emit(self._key))
        detail_row.addWidget(self._btn_check)
        layout.addLayout(detail_row)

        # Nota conectividad Kali
        self._reach_label = QLabel("")
        self._reach_label.setObjectName("label_secondary")
        layout.addWidget(self._reach_label)

    def set_checking(self, checking: bool):
        self._btn_check.setEnabled(not checking)
        if checking:
            self._badge.setText("⏳  Verificando...")
            self._badge.setStyleSheet(
                "color: #f59e0b; font-size: 12px; font-weight: 600; background: transparent;"
            )

    def set_check_result(self, ip_count: int, rule_count: int, reachable: bool):
        ts = datetime.now().strftime("%H:%M:%S")
        self._ip_label.setText(f"IPs resueltas: {ip_count}   ({ts})")

        if rule_count == -1:
            self._badge.setText("⚪  No disponible (modo demo)")
            self._badge.setStyleSheet(
                "color: #5C7A95; font-size: 12px; font-weight: 600; background: transparent;"
            )
            self._rules_label.setStyleSheet(
                "color: #8AAABB; font-size: 11px; background: transparent;"
            )
            self._rules_label.setText("Reglas iptables: —")
            self._reach_label.setText("")
        elif rule_count == 0:
            self._badge.setText("🟢  ACCESIBLE — sin bloqueo activo")
            self._badge.setStyleSheet(
                "color: #22c55e; font-size: 12px; font-weight: 600; background: transparent;"
            )
            self._rules_label.setStyleSheet(
                "color: #ef4444; font-weight: 600; font-size: 11px; background: transparent;"
            )
            self._rules_label.setText("Reglas iptables: 0  ← aplica las reglas primero")
        else:
            self._badge.setText("🔴  BLOQUEADO")
            self._badge.setStyleSheet(
                "color: #ef4444; font-size: 12px; font-weight: 600; background: transparent;"
            )
            self._rules_label.setStyleSheet(
                "color: #22c55e; font-weight: 600; font-size: 11px; background: transparent;"
            )
            self._rules_label.setText(f"Reglas iptables: {rule_count}  ✓ activas")

        if rule_count != -1:
            if reachable:
                self._reach_label.setStyleSheet(
                    "color: #f59e0b; font-size: 11px; background: transparent;"
                )
                self._reach_label.setText(
                    "Desde Kali: alcanzable  "
                    "(normal — Kali usa OUTPUT, no FORWARD; solo los clientes quedan bloqueados)"
                )
            else:
                self._reach_label.setStyleSheet(
                    "color: #8AAABB; font-size: 11px; background: transparent;"
                )
                self._reach_label.setText("Desde Kali: sin respuesta TCP 443")

        self._btn_check.setEnabled(True)

    def set_enabled(self, enabled: bool):
        self._toggle.setChecked(enabled)


# ─── PAGE ────────────────────────────────────────────────────────────────────

class WebsitesPage(QWidget):
    config_changed = Signal(dict)

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._workers: list   = []
        self._checking: set   = set()

        self._auto_timer = QTimer(self)
        self._auto_timer.setInterval(30_000)
        self._auto_timer.timeout.connect(self._verify_all)

        self._setup_ui()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        title_row = QHBoxLayout()
        title = QLabel("Bloqueo de sitios web")
        title.setObjectName("label_title")
        title_row.addWidget(title)
        title_row.addStretch()
        btn_verify_all = QPushButton("Verificar todos")
        btn_verify_all.setObjectName("btn_secondary")
        btn_verify_all.clicked.connect(self._verify_all)
        title_row.addWidget(btn_verify_all)
        layout.addLayout(title_row)

        self._prereq_card = _PrereqCard(self._config)
        layout.addWidget(self._prereq_card)

        blocked = self._config.get("blocked_domains", BLOCKED_DOMAINS)
        self._site_cards: dict = {}
        for key, cfg in blocked.items():
            card = SiteCard(key, cfg)
            card.toggled.connect(self._on_toggle)
            card.check_requested.connect(self._on_check_requested)
            layout.addWidget(card)
            self._site_cards[key] = card

        layout.addStretch()
        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def showEvent(self, event):
        super().showEvent(event)
        self._prereq_card.refresh()
        self._verify_all()
        if not self._auto_timer.isActive():
            self._auto_timer.start()

    def hideEvent(self, event):
        super().hideEvent(event)
        self._auto_timer.stop()

    def _verify_all(self):
        for key in self._site_cards:
            self._on_check_requested(key)

    def _on_toggle(self, key: str, enabled: bool):
        if "blocked_domains" not in self._config:
            self._config["blocked_domains"] = {}
        if key not in self._config["blocked_domains"]:
            self._config["blocked_domains"][key] = BLOCKED_DOMAINS.get(key, {})
        self._config["blocked_domains"][key]["enabled"] = enabled
        self.config_changed.emit(self._config)

    def _on_check_requested(self, key: str):
        if key in self._checking:
            return
        card = self._site_cards.get(key)
        if not card:
            return
        self._checking.add(key)
        card.set_checking(True)
        domains = (
            self._config.get("blocked_domains", BLOCKED_DOMAINS)
            .get(key, {})
            .get("domains", [])
        )
        worker = _FullCheckWorker(key, domains)
        worker.finished.connect(self._on_check_done)
        self._workers.append(worker)
        worker.start()

    def _on_check_done(self, key: str, ip_count: int, rule_count: int, reachable: bool):
        self._checking.discard(key)
        self._workers = [w for w in self._workers if w.isRunning()]
        card = self._site_cards.get(key)
        if card:
            card.set_check_result(ip_count, rule_count, reachable)

    def update_config(self, config: dict):
        self._config = config
        self._prereq_card.update_config(config)
        blocked = config.get("blocked_domains", {})
        for key, card in self._site_cards.items():
            if key in blocked:
                card.set_enabled(blocked[key].get("enabled", False))
