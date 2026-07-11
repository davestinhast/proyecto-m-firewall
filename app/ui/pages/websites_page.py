"""
Pantalla 2 — Bloqueo de sitios web
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QSizePolicy,
)
from PySide6.QtCore import Qt, QThread, Signal
from app.ui.widgets.toggle_switch import ToggleSwitch
from app.services import domain_service
from app.constants import BLOCKED_DOMAINS


class _ResolveWorker(QThread):
    finished = Signal(str, list)  # key, ips

    def __init__(self, key: str, domains: list[str]):
        super().__init__()
        self._key = key
        self._domains = domains

    def run(self):
        ips: set[str] = set()
        for domain in self._domains:
            ips.update(domain_service.resolve_domain(domain))
        self.finished.emit(self._key, sorted(ips))


class SiteCard(QFrame):
    toggled = Signal(str, bool)
    update_requested = Signal(str)

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

        # Info IPs
        self._ip_label = QLabel("IPs resueltas: —")
        self._ip_label.setObjectName("label_mono")
        layout.addWidget(self._ip_label)

        # Dominios
        domains_text = "  ".join(self._cfg.get("domains", []))
        domains_lbl = QLabel(domains_text)
        domains_lbl.setObjectName("label_secondary")
        domains_lbl.setWordWrap(True)
        layout.addWidget(domains_lbl)

        # Botones
        btn_row = QHBoxLayout()
        btn_update = QPushButton("Actualizar IPs")
        btn_update.setObjectName("btn_secondary")
        btn_update.clicked.connect(lambda: self.update_requested.emit(self._key))
        btn_row.addWidget(btn_update)
        btn_row.addStretch()
        layout.addLayout(btn_row)

    def set_ip_count(self, count: int, timestamp: str = ""):
        text = f"IPs resueltas: {count}"
        if timestamp:
            text += f"   —   última actualización: {timestamp}"
        self._ip_label.setText(text)

    def set_resolving(self, resolving: bool):
        self._ip_label.setText("Resolviendo IPs..." if resolving else self._ip_label.text())


class WebsitesPage(QWidget):
    config_changed = Signal(dict)

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._workers: list[_ResolveWorker] = []
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
            "La aplicación resuelve los dominios a IPs y bloquea los puertos TCP 80, TCP 443 y UDP 443 (QUIC)."
        )
        desc.setObjectName("label_secondary")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Tarjeta por cada servicio
        blocked = self._config.get("blocked_domains", BLOCKED_DOMAINS)
        self._site_cards: dict[str, SiteCard] = {}

        for key, cfg in blocked.items():
            card = SiteCard(key, cfg)
            card.toggled.connect(self._on_toggle)
            card.update_requested.connect(self._on_update_requested)
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

    def _on_update_requested(self, key: str):
        card = self._site_cards.get(key)
        if not card:
            return
        card.set_resolving(True)
        domains = self._config.get("blocked_domains", BLOCKED_DOMAINS).get(key, {}).get("domains", [])
        worker = _ResolveWorker(key, domains)
        worker.finished.connect(self._on_resolved)
        self._workers.append(worker)
        worker.start()

    def _on_resolved(self, key: str, ips: list[str]):
        from datetime import datetime
        card = self._site_cards.get(key)
        if card:
            card.set_ip_count(len(ips), datetime.now().strftime("%H:%M:%S"))

    def update_config(self, config: dict):
        self._config = config
