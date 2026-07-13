"""
Pantalla 5 — Registros en texto plano
"""

import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QHBoxLayout
)
from PySide6.QtCore import QTimer
from app.constants import LINUX_LOG_FILE


class LogsPage(QWidget):
    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._load_entries()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._load_entries)
        self._timer.start(4000)

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        title = QLabel("Archivo de Registros de iptables")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)

        log_file = self._config.get("log_file", LINUX_LOG_FILE)
        info_lbl = QLabel(f"Ruta: {log_file}")
        layout.addWidget(info_lbl)

        self._text_area = QTextEdit()
        self._text_area.setReadOnly(True)
        # Use simple monospace font
        self._text_area.setStyleSheet("font-family: Consolas, monospace; background-color: #ffffff; color: #000000;")
        layout.addWidget(self._text_area)

        btn_layout = QHBoxLayout()
        btn_refresh = QPushButton("Actualizar ahora")
        btn_refresh.clicked.connect(self._load_entries)
        btn_layout.addWidget(btn_refresh)
        btn_layout.addStretch()

        layout.addLayout(btn_layout)

    def _load_entries(self):
        log_file = self._config.get("log_file", LINUX_LOG_FILE)
        if not os.path.exists(log_file):
            self._text_area.setPlainText(f"[!] El archivo {log_file} no existe todavía.\nAún no hay paquetes rechazados registrados.")
            return

        try:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                # Read last lines
                lines = f.readlines()
                tail = lines[-100:]  # get last 100 lines
                self._text_area.setPlainText("".join(tail))
                
                # Scroll to bottom
                scrollbar = self._text_area.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())
        except Exception as e:
            self._text_area.setPlainText(f"Error al leer el archivo:\n{e}")

    def update_config(self, config: dict):
        self._config = config
