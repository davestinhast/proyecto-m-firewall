"""
Pantalla 6 — Registros en tiempo real
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QFileDialog, QComboBox,
)
from PySide6.QtCore import Qt, QTimer
from app.services import logging_service
from app.constants import LINUX_LOG_FILE


class LogsPage(QWidget):
    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._all_entries: list[dict] = []
        self._setup_ui()
        self._load_entries()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._load_entries)
        self._timer.start(4000)

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

        title = QLabel("Registros de paquetes rechazados")
        title.setObjectName("label_title")
        layout.addWidget(title)

        # Info ruta del log
        log_file = self._config.get("log_file", LINUX_LOG_FILE)
        info_lbl = QLabel(f"Archivo: {log_file}")
        info_lbl.setObjectName("label_mono")
        layout.addWidget(info_lbl)

        # Filtros
        filter_frame = QFrame()
        filter_frame.setObjectName("card")
        filter_layout = QHBoxLayout(filter_frame)
        filter_layout.setContentsMargins(16, 12, 16, 12)
        filter_layout.setSpacing(10)

        filter_layout.addWidget(QLabel("Buscar IP:"))
        self._search_ip = QLineEdit()
        self._search_ip.setPlaceholderText("ej: 192.168.50.10")
        self._search_ip.setMaximumWidth(180)
        self._search_ip.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self._search_ip)

        filter_layout.addWidget(QLabel("Protocolo:"))
        self._proto_filter = QComboBox()
        self._proto_filter.addItems(["Todos", "TCP", "UDP", "ICMP"])
        self._proto_filter.currentTextChanged.connect(self._apply_filters)
        filter_layout.addWidget(self._proto_filter)

        filter_layout.addWidget(QLabel("Motivo:"))
        self._reason_filter = QComboBox()
        self._reason_filter.addItems(["Todos", "Facebook", "YouTube", "Hotmail", "SSH bloqueado", "MAC bloqueada"])
        self._reason_filter.currentTextChanged.connect(self._apply_filters)
        filter_layout.addWidget(self._reason_filter)

        filter_layout.addStretch()

        btn_refresh = QPushButton("Actualizar")
        btn_refresh.setObjectName("btn_secondary")
        btn_refresh.clicked.connect(self._load_entries)
        filter_layout.addWidget(btn_refresh)

        btn_clear = QPushButton("Limpiar vista")
        btn_clear.setObjectName("btn_secondary")
        btn_clear.clicked.connect(self._clear_view)
        filter_layout.addWidget(btn_clear)

        btn_export = QPushButton("Exportar CSV")
        btn_export.setObjectName("btn_secondary")
        btn_export.clicked.connect(self._export_csv)
        filter_layout.addWidget(btn_export)

        layout.addWidget(filter_frame)

        # Contador
        self._count_label = QLabel("0 entradas")
        self._count_label.setObjectName("label_secondary")
        layout.addWidget(self._count_label)

        # Tabla
        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels(["Hora", "Origen", "Destino", "Proto", "Puerto", "Interfaz", "Motivo"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._table)

        layout.addStretch()
        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def _load_entries(self):
        log_file = self._config.get("log_file", LINUX_LOG_FILE)
        self._all_entries = logging_service.read_log_tail(200, log_file)
        self._apply_filters()

    def _apply_filters(self):
        ip_filter = self._search_ip.text().strip().lower()
        proto_filter = self._proto_filter.currentText()
        reason_filter = self._reason_filter.currentText()

        filtered = []
        for entry in self._all_entries:
            if ip_filter and ip_filter not in entry.get("src", "").lower():
                continue
            if proto_filter != "Todos" and proto_filter.lower() != entry.get("proto", "").lower():
                continue
            if reason_filter != "Todos" and reason_filter != entry.get("reason", ""):
                continue
            filtered.append(entry)

        self._table.setRowCount(len(filtered))
        for row, e in enumerate(filtered):
            self._table.setItem(row, 0, QTableWidgetItem(e.get("time", "")))
            self._table.setItem(row, 1, QTableWidgetItem(e.get("src", "")))
            self._table.setItem(row, 2, QTableWidgetItem(e.get("dst", "")))
            self._table.setItem(row, 3, QTableWidgetItem(e.get("proto", "")))
            self._table.setItem(row, 4, QTableWidgetItem(e.get("dport", "")))
            self._table.setItem(row, 5, QTableWidgetItem(e.get("in_iface", "")))
            self._table.setItem(row, 6, QTableWidgetItem(e.get("reason", "")))

        self._count_label.setText(f"{len(filtered)} entradas ({len(self._all_entries)} total)")

    def _clear_view(self):
        self._all_entries = []
        self._table.setRowCount(0)
        self._count_label.setText("Vista limpiada — el archivo de log no fue modificado.")

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Exportar registros", "iptables-log.csv", "CSV (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("Hora,Origen,Destino,Proto,Puerto,Interfaz,Motivo\n")
                for e in self._all_entries:
                    f.write(f"{e.get('time','')},{e.get('src','')},{e.get('dst','')},"
                            f"{e.get('proto','')},{e.get('dport','')},{e.get('in_iface','')},{e.get('reason','')}\n")
        except Exception as ex:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Error", str(ex))

    def update_config(self, config: dict):
        self._config = config
