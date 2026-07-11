"""
Pantalla 7 — Copias de seguridad
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox,
)
from PySide6.QtCore import Qt, Signal
from app.services import firewall_service
from app.constants import LINUX_RULES_BACKUP_DIR


class BackupsPage(QWidget):
    restore_requested = Signal(str)

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._load_backups()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(20)

        title = QLabel("Copias de seguridad")
        title.setObjectName("label_title")
        layout.addWidget(title)

        desc = QLabel(
            "Cada vez que se aplican reglas se crea una copia automática. "
            "Puedes restaurar cualquier versión anterior."
        )
        desc.setObjectName("label_secondary")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        frame = QFrame()
        frame.setObjectName("card")
        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(20, 16, 20, 16)
        frame_layout.setSpacing(12)

        top_row = QHBoxLayout()
        subtitle = QLabel("Versiones guardadas")
        subtitle.setObjectName("label_subtitle")
        top_row.addWidget(subtitle)
        top_row.addStretch()
        btn_refresh = QPushButton("Actualizar")
        btn_refresh.setObjectName("btn_secondary")
        btn_refresh.clicked.connect(self._load_backups)
        top_row.addWidget(btn_refresh)
        frame_layout.addLayout(top_row)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Archivo", "Fecha", "Reglas", "Acción"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        frame_layout.addWidget(self._table)

        layout.addWidget(frame)
        layout.addStretch()
        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def _load_backups(self):
        backups = firewall_service.list_backups()
        self._table.setRowCount(len(backups))
        for row, b in enumerate(backups):
            self._table.setItem(row, 0, QTableWidgetItem(b["name"]))
            self._table.setItem(row, 1, QTableWidgetItem(b["date"]))
            self._table.setItem(row, 2, QTableWidgetItem(str(b["rule_count"])))

            btn = QPushButton("Restaurar")
            btn.setObjectName("btn_danger")
            btn.clicked.connect(lambda _, path=b["path"]: self._restore(path))
            cell = QWidget()
            cell_layout = QHBoxLayout(cell)
            cell_layout.setContentsMargins(4, 2, 4, 2)
            cell_layout.addWidget(btn)
            self._table.setCellWidget(row, 3, cell)

        if not backups:
            self._table.setRowCount(1)
            self._table.setItem(0, 0, QTableWidgetItem("No hay copias de seguridad disponibles."))

    def _restore(self, path: str):
        reply = QMessageBox.question(
            self, "Restaurar copia",
            f"¿Restaurar reglas desde:\n{path}\n\nEsto reemplazará las reglas activas.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            ok, msg = firewall_service.restore_backup(path)
            if ok:
                QMessageBox.information(self, "Restaurado", msg)
            else:
                QMessageBox.warning(self, "Error", msg)

    def update_config(self, config: dict):
        self._config = config
