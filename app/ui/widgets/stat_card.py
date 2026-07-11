"""
Widget: tarjeta de estadística para el dashboard.
Muestra un número grande, etiqueta y color de acento.
"""

from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel
from PySide6.QtCore import Qt


class StatCard(QFrame):
    def __init__(self, title: str, value: str, accent: str = "blue", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setMinimumWidth(160)
        self.setMinimumHeight(100)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)

        self._value_label = QLabel(value)
        name_map = {
            "blue": "label_value_big",
            "green": "label_value_green",
            "red": "label_value_red",
        }
        self._value_label.setObjectName(name_map.get(accent, "label_value_big"))
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        self._title_label = QLabel(title)
        self._title_label.setObjectName("label_secondary")

        layout.addWidget(self._value_label)
        layout.addWidget(self._title_label)
        layout.addStretch()

    def set_value(self, value: str):
        self._value_label.setText(value)

    def set_title(self, title: str):
        self._title_label.setText(title)
