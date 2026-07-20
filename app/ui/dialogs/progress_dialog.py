"""
Diálogo de progreso de activación del firewall.
Muestra una interfaz estilo terminal que imprime los comandos ejecutados paso a paso.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QProgressBar, QPushButton, QFrame
)
from PySide6.QtCore import Qt
from app.workers.apply_worker import ApplyWorker

class ApplyProgressDialog(QDialog):
    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._worker = None
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("Consola de Activación de Reglas")
        self.resize(700, 480)
        self.setMinimumSize(600, 400)
        
        # Eliminar botón de cerrar (la X de la ventana) para forzar la visualización
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowCloseButtonHint)

        # Aplicar el tema oscuro global de la ventana
        self.setStyleSheet("""
            QDialog {
                background-color: #0a0a0f;
                color: #e8eaf0;
            }
            QLabel {
                color: #e8eaf0;
                font-size: 13px;
            }
            QProgressBar {
                border: 1px solid #252535;
                border-radius: 4px;
                text-align: center;
                background-color: #111118;
                color: #ffffff;
                font-weight: bold;
                height: 18px;
            }
            QProgressBar::chunk {
                background-color: #3b82f6;
                border-radius: 3px;
            }
            QTextEdit {
                background-color: #050508;
                border: 1px solid #252535;
                border-radius: 6px;
                color: #22c55e; /* Texto verde neón */
                font-family: 'Courier New', monospace;
                font-size: 11px;
            }
            QPushButton {
                background-color: #252535;
                border: 1px solid #3a3a50;
                border-radius: 4px;
                color: #e8eaf0;
                padding: 6px 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #3b82f6;
                color: #ffffff;
            }
            QPushButton:disabled {
                background-color: #111118;
                border-color: #1a1a25;
                color: #4a5060;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Encabezado
        self._title = QLabel("<b>Ejecutando Comandos del Firewall en el Núcleo</b>")
        self._title.setStyleSheet("font-size: 14px; color: #3b82f6;")
        layout.addWidget(self._title)

        # Descripción
        self._desc = QLabel("Aplicando reglas y construyendo tablas de red secuencialmente...")
        layout.addWidget(self._desc)

        # Consola Terminal
        self._terminal = QTextEdit()
        self._terminal.setReadOnly(True)
        self._terminal.setPlaceholderText("Iniciando consola de seguridad...")
        layout.addWidget(self._terminal, stretch=1)

        # Barra de progreso
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        layout.addWidget(self._progress_bar)

        # Fila inferior (Botón cerrar)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._btn_close = QPushButton("Cerrar Consola")
        self._btn_close.setEnabled(False) # Deshabilitado hasta que termine la ejecución
        self._btn_close.clicked.connect(self.accept)
        btn_row.addWidget(self._btn_close)
        layout.addLayout(btn_row)

    def start_execution(self):
        """Inicia el worker y se conecta a los eventos."""
        self._worker = ApplyWorker(self._config)
        self._worker.progress.connect(self._on_progress)
        self._worker.log_line.connect(self._on_log_line)
        self._worker.finished.connect(self._on_finished)
        self._worker.start()

    def _on_progress(self, pct: int, msg: str):
        self._progress_bar.setValue(pct)
        self._desc.setText(msg)

    def _on_log_line(self, line: str):
        self._terminal.append(line)
        # Scroll automático hacia abajo para simular consola activa
        scrollbar = self._terminal.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _on_finished(self, ok: bool, msg: str):
        self._btn_close.setEnabled(True)
        if ok:
            self._title.setText("<b>¡Activación del Firewall Completada!</b>")
            self._title.setStyleSheet("font-size: 14px; color: #22c55e;")
            self._desc.setText("El firewall está activo y operativo.")
        else:
            self._title.setText("<b>Error al aplicar las reglas</b>")
            self._title.setStyleSheet("font-size: 14px; color: #ef4444;")
            self._desc.setText(f"Ocurrió un fallo: {msg}")
