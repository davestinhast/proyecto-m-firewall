"""
Pantalla 2 — Bloqueo de sitios web
"""

import socket
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton,
)
from PySide6.QtCore import Qt, QThread, Signal
from app.ui.widgets.toggle_switch import ToggleSwitch
from app.constants import BLOCKED_DOMAINS


class _FullCheckWorker(QThread):
    """
    Resolución de IPs + conteo de reglas iptables + test TCP en un solo paso.
    """
    finished = Signal(str, int, int, bool)  # key, ip_count, rule_count, reachable

    def __init__(self, key: str, domains: list[str]):
        super().__init__()
        self._key = key
        self._domains = domains

    def run(self):
        # 1. Resolver IPs
        from app.services import domain_service
        import subprocess
        ips: set[str] = set()
        for d in self._domains:
            ips.update(domain_service.resolve_domain(d))
        ip_count = len(ips)

        # 2. Contar reglas en iptables PM_WEBBLOCK
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

        # 3. Test TCP 443
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


class SiteCard(QFrame):
    toggled = Signal(str, bool)
    check_requested = Signal(str)   # único botón: actualizar IPs + verificar estado

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

        # Fila superior: nombre + toggle
        top_row = QHBoxLayout()
        label_name = QLabel(self._cfg["label"])
        label_name.setObjectName("label_subtitle")
        top_row.addWidget(label_name)
        top_row.addStretch()
        self._toggle = ToggleSwitch()
        self._toggle.setChecked(self._cfg.get("enabled", False))
        self._toggle.toggled.connect(lambda checked: self.toggled.emit(self._key, checked))
        top_row.addWidget(self._toggle)
        layout.addLayout(top_row)

        # Descripción
        desc = QLabel(self._cfg["description"])
        desc.setObjectName("label_secondary")
        layout.addWidget(desc)

        # Dominios
        domains_text = "  ".join(self._cfg.get("domains", []))
        domains_lbl = QLabel(domains_text)
        domains_lbl.setObjectName("label_secondary")
        domains_lbl.setWordWrap(True)
        layout.addWidget(domains_lbl)

        # Fila de estado: IPs + reglas activas
        status_row = QHBoxLayout()
        self._ip_label = QLabel("IPs resueltas: —")
        self._ip_label.setObjectName("label_mono")
        status_row.addWidget(self._ip_label)
        status_row.addSpacing(24)
        self._rules_label = QLabel("Reglas en iptables: —")
        self._rules_label.setObjectName("label_mono")
        status_row.addWidget(self._rules_label)
        status_row.addStretch()
        layout.addLayout(status_row)

        # Indicador de conectividad (desde Kali)
        self._reach_label = QLabel("")
        self._reach_label.setObjectName("label_secondary")
        layout.addWidget(self._reach_label)

        # Botón único: actualizar IPs + verificar estado en un paso
        btn_row = QHBoxLayout()
        self._btn_check = QPushButton("Actualizar y verificar")
        self._btn_check.setObjectName("btn_secondary")
        self._btn_check.setToolTip("Resuelve las IPs del dominio y comprueba si las reglas están cargadas en iptables")
        self._btn_check.clicked.connect(lambda: self.check_requested.emit(self._key))
        btn_row.addWidget(self._btn_check)
        btn_row.addStretch()
        layout.addLayout(btn_row)

    def set_ip_count(self, count: int, timestamp: str = ""):
        text = f"IPs resueltas: {count}"
        if timestamp:
            text += f"   última actualización: {timestamp}"
        self._ip_label.setText(text)

    def set_resolving(self, resolving: bool):
        if resolving:
            self._ip_label.setText("Resolviendo IPs...")

    def set_checking(self, checking: bool):
        self._btn_check.setEnabled(not checking)
        if checking:
            self._ip_label.setText("Actualizando IPs...")
            self._rules_label.setText("Verificando reglas...")
            self._reach_label.setText("")

    def set_check_result(self, ip_count: int, rule_count: int, reachable: bool):
        from datetime import datetime
        self._ip_label.setText(f"IPs resueltas: {ip_count}   última actualización: {datetime.now().strftime('%H:%M:%S')}")
        # Reglas en iptables
        if rule_count == -1:
            self._rules_label.setStyleSheet(
                "color: #8AAABB; font-size: 11px; background: transparent;"
            )
            self._rules_label.setText("Reglas en iptables: no disponible (modo demo)")
        elif rule_count == 0:
            self._rules_label.setStyleSheet(
                "color: #ef4444; font-weight: 600; font-size: 11px; background: transparent;"
            )
            self._rules_label.setText("Reglas en iptables: 0  ← aplicar reglas primero")
        else:
            self._rules_label.setStyleSheet(
                "color: #22c55e; font-weight: 600; font-size: 11px; background: transparent;"
            )
            self._rules_label.setText(f"Reglas en iptables: {rule_count}  ✓ activas")

        # Conectividad desde Kali (informativo — Kali no está bloqueada por FORWARD)
        if rule_count == -1:
            self._reach_label.setText("")
        elif reachable:
            self._reach_label.setStyleSheet(
                "color: #f59e0b; font-size: 11px; background: transparent;"
            )
            self._reach_label.setText(
                "Desde Kali: alcanzable  "
                "(normal — Kali no pasa por FORWARD, solo los clientes están bloqueados)"
            )
        else:
            self._reach_label.setStyleSheet(
                "color: #8AAABB; font-size: 11px; background: transparent;"
            )
            self._reach_label.setText("Desde Kali: sin respuesta TCP 443 (sitio caído o sin internet)")

        self._btn_check.setEnabled(True)

    def set_enabled(self, enabled: bool):
        self._toggle.setChecked(enabled)


class WebsitesPage(QWidget):
    config_changed = Signal(dict)

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._workers: list[QThread] = []
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

        title = QLabel("Bloqueo de sitios web")
        title.setObjectName("label_title")
        layout.addWidget(title)

        desc = QLabel(
            "Activa o desactiva el bloqueo de cada servicio. "
            "La aplicación resuelve los dominios a IPs y bloquea TCP 80, TCP 443 y UDP 443 (QUIC). "
            "Usa 'Verificar estado' para comprobar si las reglas están cargadas en iptables."
        )
        desc.setObjectName("label_secondary")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Nota explicativa sobre el indicador
        note = QFrame()
        note.setObjectName("card_step_pending")
        note_layout = QHBoxLayout(note)
        note_layout.setContentsMargins(16, 10, 16, 10)
        note_lbl = QLabel(
            "Los clientes quedan bloqueados cuando: "
            "1) el toggle está activo  "
            "2) se pulsó 'Aplicar reglas'  "
            "3) 'Reglas en iptables' muestra un número mayor a 0"
        )
        note_lbl.setObjectName("label_secondary")
        note_lbl.setWordWrap(True)
        note_layout.addWidget(note_lbl)
        layout.addWidget(note)

        # Tarjeta por cada servicio
        blocked = self._config.get("blocked_domains", BLOCKED_DOMAINS)
        self._site_cards: dict[str, SiteCard] = {}

        for key, cfg in blocked.items():
            card = SiteCard(key, cfg)
            card.toggled.connect(self._on_toggle)
            card.check_requested.connect(self._on_check_requested)
            layout.addWidget(card)
            self._site_cards[key] = card

        layout.addStretch()
        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def _on_toggle(self, key: str, enabled: bool):
        if "blocked_domains" not in self._config:
            self._config["blocked_domains"] = {}
        if key not in self._config["blocked_domains"]:
            self._config["blocked_domains"][key] = BLOCKED_DOMAINS.get(key, {})
        self._config["blocked_domains"][key]["enabled"] = enabled
        self.config_changed.emit(self._config)

    def _on_check_requested(self, key: str):
        card = self._site_cards.get(key)
        if not card:
            return
        card.set_checking(True)
        domains = self._config.get("blocked_domains", BLOCKED_DOMAINS).get(key, {}).get("domains", [])
        worker = _FullCheckWorker(key, domains)
        worker.finished.connect(self._on_check_done)
        self._workers.append(worker)
        worker.start()

    def _on_check_done(self, key: str, ip_count: int, rule_count: int, reachable: bool):
        card = self._site_cards.get(key)
        if card:
            card.set_check_result(ip_count, rule_count, reachable)

    def update_config(self, config: dict):
        self._config = config
        blocked = config.get("blocked_domains", {})
        for key, card in self._site_cards.items():
            if key in blocked:
                card.set_enabled(blocked[key].get("enabled", False))
